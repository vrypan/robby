package xrpc

import (
	"encoding/json"
	"testing"

	"github.com/vrypan/robby/internal/lexicon"
)

// A profile record with an avatar blob, exactly as a client sends it on an
// avatar update.
const profileWithAvatarJSON = `{
	"$type": "app.bsky.actor.profile",
	"displayName": "me",
	"avatar": {
		"$type": "blob",
		"ref": {"$link": "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"},
		"mimeType": "image/jpeg",
		"size": 12345
	}
}`

// TestParseRecordProducesValidBlob is the regression guard for the avatar
// update failing with "expected a blob": parseRecord must run the record
// through atdata.UnmarshalJSON so the blob ref becomes a typed blob that
// passes Lexicon validation.
func TestParseRecordProducesValidBlob(t *testing.T) {
	rec, err := parseRecord(json.RawMessage(profileWithAvatarJSON))
	if err != nil {
		t.Fatalf("parseRecord: %v", err)
	}
	if err := lexicon.ValidateRecord(rec); err != nil {
		t.Fatalf("profile with avatar blob failed validation: %v", err)
	}
}

// TestUntypedBlobFailsValidation documents the original bug: decoding the
// same record with plain encoding/json (leaving the blob an untyped map)
// is exactly what the validator rejected.
func TestUntypedBlobFailsValidation(t *testing.T) {
	var rec map[string]any
	if err := json.Unmarshal([]byte(profileWithAvatarJSON), &rec); err != nil {
		t.Fatal(err)
	}
	if err := lexicon.ValidateRecord(rec); err == nil {
		t.Fatal("expected an untyped blob map to fail validation (the pre-fix behavior)")
	}
}

func TestParseRecordRejectsEmpty(t *testing.T) {
	if _, err := parseRecord(nil); err == nil {
		t.Fatal("empty record was accepted")
	}
}
