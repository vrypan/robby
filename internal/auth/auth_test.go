package auth

import (
	"strings"
	"testing"
)

const testSecret = "test-secret-value"

func TestAccessTokenRoundTripsCredentialKinds(t *testing.T) {
	cases := []Credential{
		{Kind: CredentialPrimary},
		{Kind: CredentialAppPassword, AppPasswordName: "phone"},
		{Kind: CredentialPrivilegedAppPassword, AppPasswordName: "laptop"},
	}
	for _, cred := range cases {
		t.Run(cred.Kind, func(t *testing.T) {
			tok, _, err := IssueAccessToken(testSecret, "did:plc:abc", "did:web:pds", 7, cred)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseAccessToken(testSecret, tok)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.DID != "did:plc:abc" || parsed.AuthVersion != 7 ||
				parsed.CredentialKind != cred.Kind || parsed.AppPasswordName != cred.AppPasswordName {
				t.Fatalf("round trip mismatch: %+v", parsed)
			}
		})
	}
}

func TestRefreshTokenCarriesCredential(t *testing.T) {
	tok, jti, _, err := IssueRefreshToken(testSecret, "did:plc:abc", "did:web:pds", 3,
		Credential{Kind: CredentialAppPassword, AppPasswordName: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRefreshToken(testSecret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.JTI != jti {
		t.Fatalf("jti mismatch: %s != %s", parsed.JTI, jti)
	}
	if parsed.AuthVersion != 3 || parsed.CredentialKind != CredentialAppPassword || parsed.AppPasswordName != "phone" {
		t.Fatalf("refresh credential mismatch: %+v", parsed)
	}
}

func TestScopeIsEnforced(t *testing.T) {
	access, _, err := IssueAccessToken(testSecret, "did:plc:abc", "did:web:pds", 1, Credential{Kind: CredentialPrimary})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRefreshToken(testSecret, access); err == nil {
		t.Fatal("an access token was accepted as a refresh token")
	}
	refresh, _, _, err := IssueRefreshToken(testSecret, "did:plc:abc", "did:web:pds", 1, Credential{Kind: CredentialPrimary})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAccessToken(testSecret, refresh); err == nil {
		t.Fatal("a refresh token was accepted as an access token")
	}
}

func TestWrongSecretRejected(t *testing.T) {
	tok, _, err := IssueAccessToken(testSecret, "did:plc:abc", "did:web:pds", 1, Credential{Kind: CredentialPrimary})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAccessToken("other-secret", tok); err == nil {
		t.Fatal("token verified under the wrong secret")
	}
}

// TestLegacyTokenRejected proves a token minted before credential provenance
// existed (no auth version, no credential kind) can no longer authenticate —
// the upgrade must invalidate legacy sessions rather than grant them privilege.
func TestLegacyTokenRejected(t *testing.T) {
	// AuthVersion 0 and empty credential kind is the pre-migration shape.
	tok, _, err := IssueAccessToken(testSecret, "did:plc:abc", "did:web:pds", 0, Credential{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParseAccessToken(testSecret, tok)
	if err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy token error = %v, want legacy rejection", err)
	}
}
