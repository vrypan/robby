package xrpc

import (
	"testing"

	"github.com/vrypan/robby/internal/lexicon"
)

// TestDefaultSeedRecordsValidate guards the account-creation seed: every
// default record must pass lexicon validation (a bad one would make every
// new account fail to create), and the notification declaration must default
// to "followers" at rkey "self".
func TestDefaultSeedRecordsValidate(t *testing.T) {
	seeds := defaultSeedRecords()
	if len(seeds) == 0 {
		t.Fatal("expected at least one seed record")
	}

	var sawDeclaration bool
	for _, op := range seeds {
		if op.Record["$type"] != op.Collection {
			t.Fatalf("%s: $type %v does not match collection", op.Collection, op.Record["$type"])
		}
		if err := lexicon.ValidateRecord(op.Record); err != nil {
			t.Fatalf("seed record %s failed lexicon validation: %v", op.Collection, err)
		}
		if op.Collection == "app.bsky.notification.declaration" {
			sawDeclaration = true
			if op.RKey != "self" {
				t.Fatalf("declaration rkey = %q, want self", op.RKey)
			}
			if op.Record["allowSubscriptions"] != "followers" {
				t.Fatalf("allowSubscriptions = %v, want followers", op.Record["allowSubscriptions"])
			}
		}
	}
	if !sawDeclaration {
		t.Fatal("expected an app.bsky.notification.declaration seed record")
	}
}
