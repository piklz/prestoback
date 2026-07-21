package backup

// prestobackremote.go — the "prestoback" RemoteTarget kind's actual
// network client: completing a pairing handshake as the pusher, and
// pushing/listing/pulling backup archives against another PrestoBack
// instance's API. The cryptographic protocol itself (what gets signed,
// what gets verified, why) lives in internal/config/nodeidentity.go and
// remotepairing.go — this file is the HTTP transport around it, the same
// split sftpconn.go/s3.go already have between "the protocol" and "the
// wire format."

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pi/prestoback/internal/config"
)

var prestobackHTTPClient = &http.Client{Timeout: remoteOpTimeout}

// PrestoBackPairResult is what a successful pairing hands back — exactly
// the fields a RemoteTarget{Kind: "prestoback"} needs.
type PrestoBackPairResult struct {
	PinnedNodeID    string
	PinnedPublicKey string // base64
	PushCredential  string
}

// PairWithPrestoBackRemote completes a pairing handshake AS THE PUSHER
// against a receiver's baseURL, using the secret + expectedNodeID a QR
// code provided (the out-of-band channel this whole scheme's MITM
// resistance rests on — see nodeidentity.go's package comment). myCfg is
// THIS instance's own config, used only for its NodeID/public key/signing
// — never anything else.
//
// This function performs both checks that matter and returns an error
// (never a "trust it anyway" fallback) if either fails:
//  1. the public key the receiver returned actually produces the NodeID
//     the QR said to expect, and
//  2. the signature over the binding message actually verifies against
//     that key.
//
// Only if both hold does this function return a result at all.
func PairWithPrestoBackRemote(ctx context.Context, baseURL, secret, expectedNodeID string, myCfg *config.Config) (PrestoBackPairResult, error) {
	nonce, err := config.GenerateChallengeNonce()
	if err != nil {
		return PrestoBackPairResult{}, err
	}
	myNodeID := myCfg.NodeID()
	myPubKeyB64 := base64.StdEncoding.EncodeToString(myCfg.NodePublicKey())
	if myNodeID == "" {
		return PrestoBackPairResult{}, fmt.Errorf("this instance has no node identity yet")
	}

	reqBody := config.RemotePairingClaimRequest{
		Secret:          secret,
		PusherNodeID:    myNodeID,
		PusherPublicKey: myPubKeyB64,
		ChallengeNonce:  nonce,
	}
	var resp config.RemotePairingClaimResponse
	if err := prestobackPostJSON(ctx, baseURL+"/api/remote-pairing/claim", reqBody, &resp); err != nil {
		return PrestoBackPairResult{}, fmt.Errorf("pairing request failed: %w", err)
	}

	// THE check — see package comment. Refuses to proceed on any failure
	// here, no matter how the request/response otherwise looked.
	if err := config.VerifyRemotePairingResponse(resp, expectedNodeID, myNodeID, nonce, secret); err != nil {
		return PrestoBackPairResult{}, err
	}

	return PrestoBackPairResult{
		PinnedNodeID:    resp.ReceiverNodeID,
		PinnedPublicKey: resp.ReceiverPublicKey,
		PushCredential:  resp.PushCredential,
	}, nil
}

// prestobackChallenge re-verifies a PAIRED target's identity against its
// PINNED NodeID/public key (from a completed pairing — no QR involved
// this time, the pin itself is the trust anchor). Called before every
// reachability check and every push, so a MITM that shows up only after
// pairing was done safely is caught too, not just one during the
// original handshake — see remotepairing.go's package comment for why
// this matters as much as the pairing-time check.
func prestobackChallenge(ctx context.Context, t RemoteTarget) error {
	nonce, err := config.GenerateChallengeNonce()
	if err != nil {
		return err
	}
	var resp config.RemoteChallengeResponse
	if err := prestobackPostJSON(ctx, t.PrestoBackURL+"/api/remote-pairing/challenge", config.RemoteChallengeRequest{Nonce: nonce}, &resp); err != nil {
		return fmt.Errorf("could not reach %s: %w", t.Name, err)
	}
	if err := config.VerifyRemoteChallengeResponse(resp, nonce, t.PrestoBackPinnedNodeID); err != nil {
		// Deliberately not wrapped further — VerifyRemoteChallengeResponse's
		// error text is already written to be shown directly to the user
		// (see its doc comment), the same "safe to surface as-is" contract
		// sftpconn.go's KnownHostsPath verifier follows for a changed SSH
		// host key.
		return err
	}
	return nil
}

func prestobackPostJSON(ctx context.Context, url string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := prestobackHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// prestobackPushFile streams localPath to the receiver's backup-receive
// endpoint, authenticated with this target's pinned push credential.
// Called only after prestobackChallenge has already succeeded for this
// operation (see RemoteReachable/PushFile's dispatch in remote.go, which
// always challenges before pushing).
func prestobackPushFile(ctx context.Context, localPath, appID string, t RemoteTarget) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}

	name := filepath.Base(localPath)
	q := url.Values{}
	q.Set("app", appID)
	q.Set("name", name)
	reqURL := strings.TrimRight(t.PrestoBackURL, "/") + "/api/remote-receive/backup?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, f)
	if err != nil {
		return "", err
	}
	req.ContentLength = info.Size()
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Push-Credential", t.PrestoBackPushCredential)

	resp, err := prestobackHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var out struct {
		Path string `json:"path"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Path, nil
}

func prestobackListFiles(ctx context.Context, t RemoteTarget, appID string) ([]RemoteFile, error) {
	q := url.Values{}
	q.Set("app", appID)
	reqURL := strings.TrimRight(t.PrestoBackURL, "/") + "/api/remote-receive/list?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Push-Credential", t.PrestoBackPushCredential)
	resp, err := prestobackHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	var out []RemoteFile
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// prestobackOpenDownload opens a streaming download of one archive from
// the receiver — returns an io.ReadCloser so PullArchive's case can use
// the exact same temp-file-then-rename pattern the sftp/s3 cases already
// use, rather than a higher-level helper duplicating that logic.
func prestobackOpenDownload(ctx context.Context, appID, name string, t RemoteTarget) (io.ReadCloser, error) {
	q := url.Values{}
	q.Set("app", appID)
	q.Set("name", name)
	reqURL := strings.TrimRight(t.PrestoBackURL, "/") + "/api/remote-receive/download?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Push-Credential", t.PrestoBackPushCredential)
	resp, err := prestobackHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(errBody)))
	}
	return resp.Body, nil
}

// prestobackReachable is RemoteReachable's "prestoback" case — just the
// identity challenge, since a successful, verified challenge response
// already proves the receiver is up, reachable, and still who it claims
// to be, all in one round trip.
func prestobackReachable(t RemoteTarget) error {
	if t.PrestoBackURL == "" || t.PrestoBackPinnedNodeID == "" || t.PrestoBackPushCredential == "" {
		return fmt.Errorf("prestoback target %q is not fully paired", t.Name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return prestobackChallenge(ctx, t)
}
