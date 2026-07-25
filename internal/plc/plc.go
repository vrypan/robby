// Package plc builds, signs, and submits did:plc operations against a
// plc.directory-compatible server.
package plc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	cbornode "github.com/ipfs/go-ipld-cbor"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, IdleConnTimeout: 90 * time.Second}}}
}

// OpFields are the mutable contents of a did:plc operation.
type OpFields struct {
	RotationKeys        []string
	VerificationMethods map[string]any
	AlsoKnownAs         []string
	Services            map[string]any
}

// SignOp builds and signs a did:plc operation. prevOpCID is nil for a
// genesis ("create") operation, or the CID (string form) of the
// account's previous operation for an update.
func SignOp(rotationKey atcrypto.PrivateKey, prevOpCID *string, fields OpFields) (signedOp map[string]any, err error) {
	var prev any
	if prevOpCID != nil {
		prev = *prevOpCID
	}

	unsigned := map[string]any{
		"type":                "plc_operation",
		"rotationKeys":        fields.RotationKeys,
		"verificationMethods": fields.VerificationMethods,
		"alsoKnownAs":         fields.AlsoKnownAs,
		"services":            fields.Services,
		"prev":                prev,
	}

	unsignedBytes, err := cbornode.DumpObject(unsigned)
	if err != nil {
		return nil, fmt.Errorf("encoding operation: %w", err)
	}

	sig, err := rotationKey.HashAndSign(unsignedBytes)
	if err != nil {
		return nil, fmt.Errorf("signing operation: %w", err)
	}

	signedOp = make(map[string]any, len(unsigned)+1)
	for k, v := range unsigned {
		signedOp[k] = v
	}
	signedOp["sig"] = base64.RawURLEncoding.EncodeToString(sig)
	return signedOp, nil
}

// Genesis builds and signs a did:plc "create" operation for a brand-new
// account, computes the resulting did:plc identifier, and returns both the
// DID and the signed operation ready for submission.
func Genesis(rotationKey atcrypto.PrivateKey, signingKey atcrypto.PublicKey, handle, pdsURL string) (did string, signedOp map[string]any, err error) {
	rotationPub, err := rotationKey.PublicKey()
	if err != nil {
		return "", nil, fmt.Errorf("deriving rotation public key: %w", err)
	}

	signedOp, err = SignOp(rotationKey, nil, OpFields{
		RotationKeys:        []string{rotationPub.DIDKey()},
		VerificationMethods: map[string]any{"atproto": signingKey.DIDKey()},
		AlsoKnownAs:         []string{"at://" + handle},
		Services: map[string]any{
			"atproto_pds": map[string]any{
				"type":     "AtprotoPersonalDataServer",
				"endpoint": pdsURL,
			},
		},
	})
	if err != nil {
		return "", nil, err
	}

	signedBytes, err := cbornode.DumpObject(signedOp)
	if err != nil {
		return "", nil, fmt.Errorf("encoding signed operation: %w", err)
	}

	did = didFromOp(signedBytes)
	return did, signedOp, nil
}

func didFromOp(signedCBOR []byte) string {
	sum := sha256.Sum256(signedCBOR)
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum[:])
	return "did:plc:" + strings.ToLower(b32[:24])
}

// Submit POSTs a signed operation to the PLC server for the given DID.
func (c *Client) Submit(ctx context.Context, did string, signedOp map[string]any) error {
	body, err := json.Marshal(signedOp)
	if err != nil {
		return fmt.Errorf("encoding operation as JSON: %w", err)
	}

	url := c.BaseURL + "/" + did
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("submitting PLC operation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("PLC server rejected operation (status %d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

type auditLogEntry struct {
	CID       string         `json:"cid"`
	Operation map[string]any `json:"operation"`
}

// GetLastOp fetches the DID's operation log and returns the most recent
// entry's CID and operation body — needed as the "prev" pointer (and, for
// fields the caller isn't changing, as the source of truth) when building
// an update operation.
func (c *Client) GetLastOp(ctx context.Context, did string) (cidStr string, operation map[string]any, err error) {
	url := c.BaseURL + "/" + did + "/log/audit"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("fetching PLC audit log: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", nil, fmt.Errorf("PLC server rejected audit log request (status %d): %s", resp.StatusCode, string(body))
	}

	var entries []auditLogEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return "", nil, fmt.Errorf("decoding PLC audit log: %w", err)
	}
	if len(entries) == 0 {
		return "", nil, fmt.Errorf("no PLC operations found for %s", did)
	}
	last := entries[len(entries)-1]
	if last.CID == "" {
		return "", nil, fmt.Errorf("PLC audit log entry missing cid")
	}
	return last.CID, last.Operation, nil
}
