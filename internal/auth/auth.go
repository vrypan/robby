// Package auth implements password hashing and access/refresh token
// issuance and verification for pds-light.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/scrypt"
)

const (
	AccessTokenTTL  = 2 * time.Hour
	RefreshTokenTTL = 90 * 24 * time.Hour

	scopeAccess  = "com.atproto.access"
	scopeRefresh = "com.atproto.refresh"

	scryptN      = 32768
	scryptR      = 8
	scryptP      = 1
	scryptKeyLen = 32
	saltLen      = 16
)

// HashPassword derives a scrypt hash of password and encodes it (with
// parameters and salt) as a single string suitable for storage.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	hash, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s",
		scryptN, scryptR, scryptP,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks password against a hash produced by HashPassword.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false, fmt.Errorf("unrecognized password hash format")
	}
	var n, r, p int
	if _, err := fmt.Sscanf(parts[1], "%d", &n); err != nil {
		return false, err
	}
	if _, err := fmt.Sscanf(parts[2], "%d", &r); err != nil {
		return false, err
	}
	if _, err := fmt.Sscanf(parts[3], "%d", &p); err != nil {
		return false, err
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}
	got, err := scrypt.Key([]byte(password), salt, n, r, p, len(want))
	if err != nil {
		return false, fmt.Errorf("hashing password: %w", err)
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

type claims struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

// IssueAccessToken creates a stateless HS256 access JWT for did.
func IssueAccessToken(secret, did, serviceDID string) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(AccessTokenTTL)
	c := claims{
		Scope: scopeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   did,
			Audience:  jwt.ClaimStrings{serviceDID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing access token: %w", err)
	}
	return tok, exp, nil
}

// IssueRefreshToken creates an HS256 refresh JWT for did, along with the
// jti that the caller should store (hashed) in the DB for revocation.
func IssueRefreshToken(secret, did, serviceDID string) (token, jti string, expiresAt time.Time, err error) {
	jtiBytes := make([]byte, 16)
	if _, err = rand.Read(jtiBytes); err != nil {
		return "", "", time.Time{}, fmt.Errorf("generating jti: %w", err)
	}
	jti = hex.EncodeToString(jtiBytes)

	now := time.Now()
	exp := now.Add(RefreshTokenTTL)
	c := claims{
		Scope: scopeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   did,
			Audience:  jwt.ClaimStrings{serviceDID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        jti,
		},
	}
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("signing refresh token: %w", err)
	}
	return token, jti, exp, nil
}

// ParsedToken holds the fields callers need from a verified access or
// refresh token.
type ParsedToken struct {
	DID   string
	JTI   string
	Scope string
}

func parse(secret, tokenString, wantScope string) (*ParsedToken, error) {
	c := &claims{}
	_, err := jwt.ParseWithClaims(tokenString, c, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if c.Scope != wantScope {
		return nil, fmt.Errorf("unexpected token scope: %s", c.Scope)
	}
	return &ParsedToken{DID: c.Subject, JTI: c.ID, Scope: c.Scope}, nil
}

// ParseAccessToken verifies signature, expiry, and scope for an access JWT.
func ParseAccessToken(secret, tokenString string) (*ParsedToken, error) {
	return parse(secret, tokenString, scopeAccess)
}

// ParseRefreshToken verifies signature, expiry, and scope for a refresh JWT.
func ParseRefreshToken(secret, tokenString string) (*ParsedToken, error) {
	return parse(secret, tokenString, scopeRefresh)
}

// HashToken returns a stable, non-reversible identifier for a token's jti,
// suitable for storage/lookup without keeping the raw token value.
func HashToken(jti string) string {
	sum := sha256.Sum256([]byte(jti))
	return hex.EncodeToString(sum[:])
}
