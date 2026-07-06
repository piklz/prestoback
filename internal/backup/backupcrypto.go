package backup

// backupcrypto.go — optional at-rest encryption for backup archives.
//
// Design goals, in order:
//   1. Streaming — must handle multi-GB archives without buffering the
//      whole file in memory (same constraint sha256File already respects
//      in engine.go).
//   2. No new external dependencies — everything here is stdlib only
//      (crypto/aes, crypto/cipher, crypto/hmac, crypto/sha256, crypto/rand).
//      Deliberately NOT using golang.org/x/crypto/scrypt or /pbkdf2, even
//      though those exist and are fine to depend on in general — avoiding
//      the extra module keeps this feature self-contained and easy to
//      audit as one file.
//   3. Authenticated — a corrupted or tampered archive must fail to
//      decrypt loudly, not silently produce garbage. AES-CTR alone gives no
//      authentication (it's a malleable stream cipher), so this uses the
//      standard encrypt-then-MAC construction: AES-256-CTR for bulk
//      encryption, HMAC-SHA256 over the ciphertext for authentication,
//      using two independently-derived subkeys (never reuse one key for
//      both encryption and authentication).
//
// File format written by EncryptStream:
//
//   [salt: 16 bytes][iv: 16 bytes][ciphertext: N bytes][hmac: 32 bytes]
//
// salt is random per-file, used to derive both the AES key and the HMAC key
// from the user's passphrase via PBKDF2-HMAC-SHA256. iv is the random CTR
// nonce. The trailing HMAC covers salt + iv + ciphertext, so a swapped
// salt/iv or truncated file is also caught, not just bit-flips within the
// ciphertext itself.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"hash"
	"io"
)

const (
	saltSize       = 16
	ivSize         = 16 // AES block size, used as the CTR IV
	hmacSize       = sha256.Size
	pbkdf2Iterations = 200_000 // OWASP-recommended floor for PBKDF2-HMAC-SHA256 as of 2023
	aesKeySize     = 32 // AES-256
	hmacKeySize    = 32 // HMAC-SHA256
)

// ErrAuthenticationFailed means the archive's HMAC didn't match — either the
// passphrase is wrong, or the file was corrupted/tampered with after
// encryption. Callers should treat this identically to "wrong password":
// there's no way to distinguish the two cases, and none should be implied
// to the user (see auth.go's constant-time comparison philosophy in
// spirit — we don't want to leak "the passphrase was right but the file is
// corrupt" vs "the passphrase was wrong", since encoding that distinction
// in behavior often turns into an oracle).
var ErrAuthenticationFailed = errors.New("backup: authentication failed — wrong passphrase or corrupted archive")

// deriveKeys runs PBKDF2-HMAC-SHA256 once over the passphrase+salt to
// produce enough key material for both the AES key and the HMAC key,
// splitting the output rather than deriving twice — one KDF pass, two
// independent-looking subkeys sliced from its output.
func deriveKeys(passphrase string, salt []byte) (aesKey, hmacKey []byte) {
	out := pbkdf2HMACSHA256([]byte(passphrase), salt, pbkdf2Iterations, aesKeySize+hmacKeySize)
	return out[:aesKeySize], out[aesKeySize:]
}

// pbkdf2HMACSHA256 is a minimal PBKDF2 implementation (RFC 8018) using
// HMAC-SHA256 as the PRF. Implemented directly rather than importing
// golang.org/x/crypto/pbkdf2 to keep this feature dependency-free — it's
// ~25 lines and the algorithm is fully specified, not worth a module for.
func pbkdf2HMACSHA256(password, salt []byte, iterations, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		dk = append(dk, pbkdf2Block(prf, salt, iterations, block)...)
	}
	return dk[:keyLen]
}

func pbkdf2Block(prf hash.Hash, salt []byte, iterations, blockNum int) []byte {
	blockIndex := []byte{
		byte(blockNum >> 24), byte(blockNum >> 16), byte(blockNum >> 8), byte(blockNum),
	}

	prf.Reset()
	prf.Write(salt)
	prf.Write(blockIndex)
	u := prf.Sum(nil)

	result := make([]byte, len(u))
	copy(result, u)

	for i := 2; i <= iterations; i++ {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(nil)
		for j := range result {
			result[j] ^= u[j]
		}
	}
	return result
}

// EncryptStream reads plaintext from src and writes an encrypted, MAC'd
// archive to dst, using a key derived from passphrase. Streams block-by-block
// via cipher.StreamWriter — safe for multi-GB archives, no full-file
// buffering.
func EncryptStream(dst io.Writer, src io.Reader, passphrase string) error {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	aesKey, hmacKey := deriveKeys(passphrase, salt)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, hmacKey)

	if _, err := dst.Write(salt); err != nil {
		return err
	}
	if _, err := dst.Write(iv); err != nil {
		return err
	}
	mac.Write(salt)
	mac.Write(iv)

	// Tee ciphertext into both the output file and the running HMAC as we
	// go, rather than buffering the whole file to MAC it afterward.
	writer := io.MultiWriter(dst, mac)
	streamWriter := &cipher.StreamWriter{S: stream, W: writer}
	if _, err := io.Copy(streamWriter, src); err != nil {
		return err
	}

	if _, err := dst.Write(mac.Sum(nil)); err != nil {
		return err
	}
	return nil
}

// DecryptStream is EncryptStream's inverse. It requires a io.ReadSeeker
// because the trailing HMAC must be read and verified BEFORE any plaintext
// is released to dst — otherwise a truncated or tampered archive could
// partially "succeed" into dst before the corruption is detected partway
// through. That means the full ciphertext is read twice (once to compute
// the HMAC, once to decrypt) — an acceptable tradeoff for correctness on
// something that only runs once per restore, not on every backup.
func DecryptStream(dst io.Writer, src io.ReadSeeker, passphrase string) error {
	header := make([]byte, saltSize+ivSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return err
	}
	salt, iv := header[:saltSize], header[saltSize:]

	end, err := src.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	ciphertextLen := end - int64(len(header)) - int64(hmacSize)
	if ciphertextLen < 0 {
		return errors.New("backup: encrypted archive is too short to be valid")
	}

	aesKey, hmacKey := deriveKeys(passphrase, salt)

	// Pass 1: verify the HMAC over salt+iv+ciphertext before releasing
	// anything to dst.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(salt)
	mac.Write(iv)
	if _, err := src.Seek(int64(len(header)), io.SeekStart); err != nil {
		return err
	}
	if _, err := io.CopyN(mac, src, ciphertextLen); err != nil {
		return err
	}
	storedMAC := make([]byte, hmacSize)
	if _, err := io.ReadFull(src, storedMAC); err != nil {
		return err
	}
	if !hmac.Equal(mac.Sum(nil), storedMAC) {
		return ErrAuthenticationFailed
	}

	// Pass 2: decrypt now that authentication has passed.
	if _, err := src.Seek(int64(len(header)), io.SeekStart); err != nil {
		return err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, iv)
	streamReader := &cipher.StreamReader{S: stream, R: io.LimitReader(src, ciphertextLen)}
	_, err = io.Copy(dst, streamReader)
	return err
}
