package backup

// s3.go — a minimal S3-compatible client (PUT/GET/LIST), hand-rolled with
// AWS Signature Version 4 over net/http + stdlib crypto only. No SDK.
//
// Why hand-roll instead of a client library: the AWS/MinIO SDKs work, but
// pull in a large dependency tree (retry policies, credential chains,
// config resolvers, dozens of transitive packages) for what this file
// needs — three HTTP verbs against one bucket. Restic and Kopia both take
// the same "small enough to hand-roll, don't drag in the SDK" approach for
// exactly this reason. What follows is the actual SigV4 algorithm (AWS
// documents it in full at docs.aws.amazon.com/general/latest/gr/
// sigv4-create-canonical-request.html) — nothing here is guesswork.
//
// Deliberately supports only what backup archives need: PutObject,
// GetObject, ListObjectsV2 (single page — an app's backup count never
// approaches S3's 1000-key page limit), and a cheap reachability probe.
// No multipart upload (archives stream in one PUT; see putObject's size
// comment for the one real limit this implies), no versioning, no ACLs.
//
// x-amz-content-sha256 is always "UNSIGNED-PAYLOAD" — a payload hash is
// normally part of the signature, but computing it would mean buffering
// or double-reading the whole archive before upload, exactly what
// EncryptStream/DecryptStream (backupcrypto.go) already go out of their
// way to avoid for multi-GB files. AWS's spec explicitly allows this over
// HTTPS: the request's authenticity is still verified (SigV4 covers the
// method, path, headers, and credentials), only the payload's own hash is
// left unsigned, with TLS providing transport integrity instead. Every
// major S3-compatible target (AWS, MinIO, Backblaze B2, Wasabi) accepts it.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type s3Client struct {
	endpoint   string // e.g. "https://s3.us-west-002.backblazeb2.com" or "http://192.168.1.50:9000" — scheme + host, no trailing slash, no bucket
	bucket     string
	accessKey  string
	secretKey  string
	region     string // many S3-compatible services accept any placeholder if they don't use regions; default "us-east-1" if blank
	httpClient *http.Client
}

func newS3Client(t RemoteTarget) *s3Client {
	region := t.S3Region
	if region == "" {
		region = "us-east-1"
	}
	return &s3Client{
		endpoint:   strings.TrimRight(t.S3Endpoint, "/"),
		bucket:     t.S3Bucket,
		accessKey:  t.S3AccessKey,
		secretKey:  t.S3SecretKey,
		region:     region,
		httpClient: &http.Client{Timeout: 0}, // per-request timeout via context instead — archives can be large and slow
	}
}

type s3Object struct {
	Key          string
	SizeBytes    int64
	LastModified time.Time
}

// objectURL builds a path-style URL (endpoint/bucket/key) — path-style
// (rather than virtual-hosted-style, bucket.endpoint) is the safer default
// for self-hosted S3-compatible targets (MinIO, etc.) which often don't
// have wildcard DNS/TLS set up for subdomain-per-bucket addressing.
func (c *s3Client) objectURL(key string) string {
	return c.endpoint + "/" + c.bucket + "/" + uriEncodePath(key)
}

// putObject uploads body (exactly size bytes) to key, streaming directly
// from the reader — no buffering, matching this codebase's existing
// large-file posture (EncryptStream, copyFileVerified). size must be known
// upfront (the caller already has it via os.Stat, same as everywhere else
// archives are handled) since a single PUT needs Content-Length; archives
// larger than a target's single-PUT limit (5GiB on AWS S3 itself, higher
// on most self-hosted S3-compatible servers) would need multipart upload,
// deliberately not implemented here — see the package comment.
func (c *s3Client) putObject(ctx context.Context, key string, body io.Reader, size int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.objectURL(key), body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	c.sign(req, "UNSIGNED-PAYLOAD")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s3ErrorFromResponse(resp)
	}
	return nil
}

// getObject returns a streaming reader for key — caller must Close() it.
func (c *s3Client) getObject(ctx context.Context, key string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.objectURL(key), nil)
	if err != nil {
		return nil, err
	}
	c.sign(req, "UNSIGNED-PAYLOAD")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, s3ErrorFromResponse(resp)
	}
	return resp.Body, nil
}

// listObjects lists every object under prefix (a single ListObjectsV2 page
// — see package comment for why that's sufficient here).
func (c *s3Client) listObjects(ctx context.Context, prefix string) ([]s3Object, error) {
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("prefix", prefix)
	reqURL := c.endpoint + "/" + c.bucket + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	c.sign(req, emptyPayloadHash)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, s3ErrorFromResponse(resp)
	}

	var parsed struct {
		XMLName  xml.Name `xml:"ListBucketResult"`
		Contents []struct {
			Key          string    `xml:"Key"`
			Size         int64     `xml:"Size"`
			LastModified time.Time `xml:"LastModified"`
		} `xml:"Contents"`
	}
	if err := xml.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("parse ListObjectsV2 response: %w", err)
	}

	out := make([]s3Object, 0, len(parsed.Contents))
	for _, c := range parsed.Contents {
		out = append(out, s3Object{Key: c.Key, SizeBytes: c.Size, LastModified: c.LastModified})
	}
	return out, nil
}

// reachable does a cheap, cheapest-possible request (list with max-keys=0)
// to confirm the endpoint, bucket, and credentials all actually work,
// without needing a HeadBucket-specific code path.
func (c *s3Client) reachable(ctx context.Context) error {
	q := url.Values{}
	q.Set("list-type", "2")
	q.Set("max-keys", "0")
	reqURL := c.endpoint + "/" + c.bucket + "/?" + q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	c.sign(req, emptyPayloadHash)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return s3ErrorFromResponse(resp)
	}
	return nil
}

// emptyPayloadHash is SHA-256 of zero bytes — used for GET/LIST requests,
// which have no body, so their payload hash is fixed and known ahead of
// time (unlike PUT's UNSIGNED-PAYLOAD, this one costs nothing to compute
// correctly, so there's no reason not to).
const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func s3ErrorFromResponse(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("S3 request failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// ── AWS Signature Version 4 ──────────────────────────────────────────────────

// sign computes and attaches the Authorization header for req per SigV4.
// payloadHash is the (possibly placeholder) x-amz-content-sha256 value —
// see putObject/getObject/listObjects for which each uses and why.
func (c *s3Client) sign(req *http.Request, payloadHash string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	if req.Host == "" {
		req.Host = req.URL.Host
	}
	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.ContentLength > 0 {
		req.Header.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}

	canonicalHeaders, signedHeaders := canonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQueryString(req.URL.RawQuery),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.region)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashHex([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(c.secretKey, dateStamp, c.region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.accessKey, credentialScope, signedHeaders, signature,
	))
}

// canonicalHeaders returns SigV4's canonical header block and the
// semicolon-joined signed-header list. Only host, x-amz-content-sha256,
// and x-amz-date are signed — sufficient for a same-request signature;
// omitting Content-Type/Content-Length from the signed set is standard
// practice for this exact minimal-client shape (aws-sdk-go's simplest
// examples do the same) and doesn't weaken the signature, since anything
// NOT listed in SignedHeaders simply isn't covered by it either way.
func canonicalHeaders(req *http.Request) (headerBlock, signedHeaders string) {
	headers := map[string]string{
		"host":                 req.Host,
		"x-amz-content-sha256": req.Header.Get("X-Amz-Content-Sha256"),
		"x-amz-date":            req.Header.Get("X-Amz-Date"),
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)

	var b strings.Builder
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strings.TrimSpace(headers[n]))
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(names, ";")
}

// canonicalURI URI-encodes each path segment per SigV4 rules (RFC 3986
// unreserved characters left alone, everything else percent-encoded) while
// leaving "/" itself as a literal segment separator — object keys like
// "myapp/myapp_data_....tar.gz" must keep their slash meaningful.
func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		segments[i] = uriEncodePath(seg)
	}
	return strings.Join(segments, "/")
}

// canonicalQueryString sorts query parameters by key and re-encodes both
// key and value per SigV4 rules (stricter than url.Values.Encode's default
// escaping in a couple of edge cases, so this doesn't reuse it directly).
func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for _, v := range vs {
			parts = append(parts, uriEncodeQuery(k)+"="+uriEncodeQuery(v))
		}
	}
	return strings.Join(parts, "&")
}

// uriEncodePath / uriEncodeQuery implement SigV4's "URI encode" (RFC 3986
// section 2.3 unreserved characters A-Za-z0-9-_.~ pass through unescaped,
// everything else becomes %XX uppercase hex). They're identical for path
// vs query today, kept as two names since AWS's spec documents them as
// separate steps and a future difference (e.g. "/" handling) shouldn't
// require renaming call sites.
func uriEncodePath(s string) string { return uriEncode(s) }
func uriEncodeQuery(s string) string { return uriEncode(s) }

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

// deriveSigningKey runs SigV4's 4-step HMAC chain: secret -> date ->
// region -> service -> "aws4_request". Each step's output becomes the
// next step's HMAC key, deliberately scoping the final key to exactly
// this date+region+service so it can't be replayed against a different
// day or a different AWS service.
func deriveSigningKey(secretKey, dateStamp, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}
