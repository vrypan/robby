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

	cbornode "github.com/ipfs/go-ipld-cbor"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

type Client struct {
	BaseURL    string
	HTTPClient *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), HTTPClient: http.DefaultClient}
}

// Genesis builds and signs a did:plc "create" operation for a brand-new
// account, computes the resulting did:plc identifier, and returns both the
// DID and the signed operation ready for submission.
func Genesis(rotationKey atcrypto.PrivateKey, signingKey atcrypto.PublicKey, handle, pdsURL string) (did string, signedOp map[string]any, err error) {
	rotationPub, err := rotationKey.PublicKey()
	if err != nil {
		return "", nil, fmt.Errorf("deriving rotation public key: %w", err)
	}

	unsigned := map[string]any{
		"type":         "plc_operation",
		"rotationKeys": []string{rotationPub.DIDKey()},
		"verificationMethods": map[string]any{
			"atproto": signingKey.DIDKey(),
		},
		"alsoKnownAs": []string{"at://" + handle},
		"services": map[string]any{
			"atproto_pds": map[string]any{
				"type":     "AtprotoPersonalDataServer",
				"endpoint": pdsURL,
			},
		},
		"prev": nil,
	}

	unsignedBytes, err := cbornode.DumpObject(unsigned)
	if err != nil {
		return "", nil, fmt.Errorf("encoding operation: %w", err)
	}

	sig, err := rotationKey.HashAndSign(unsignedBytes)
	if err != nil {
		return "", nil, fmt.Errorf("signing operation: %w", err)
	}

	signedOp = map[string]any{}
	for k, v := range unsigned {
		signedOp[k] = v
	}
	signedOp["sig"] = base64.RawURLEncoding.EncodeToString(sig)

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
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("PLC server rejected operation (status %d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}
