// Package lexicon provides the com.atproto.* / app.bsky.* Lexicon schema
// catalog used to validate records before they're written to a repo.
//
// Schema JSON files under data/ are vendored from the indigo module
// (lexicons/com, lexicons/app) so validation works without any network
// access or GOPATH dependency at runtime.
package lexicon

import (
	"embed"
	"fmt"
	"sync"

	indigolexicon "github.com/bluesky-social/indigo/atproto/lexicon"
)

//go:embed data
var lexiconFS embed.FS

var (
	once    sync.Once
	catalog *indigolexicon.BaseCatalog
	loadErr error
)

// Catalog returns the shared, lazily-loaded Lexicon catalog.
func Catalog() (*indigolexicon.BaseCatalog, error) {
	once.Do(func() {
		c := indigolexicon.NewBaseCatalog()
		if err := c.LoadEmbedFS(lexiconFS); err != nil {
			loadErr = fmt.Errorf("loading embedded lexicon catalog: %w", err)
			return
		}
		catalog = c
	})
	return catalog, loadErr
}

// ValidateRecord validates recordData (an atproto "loosely-typed data"
// map, as produced by atdata.UnmarshalJSON) against the Lexicon schema
// named by its "$type" field. Unknown NSIDs (no schema in the catalog)
// are allowed through unvalidated, since pds-light must accept records
// for lexicons it doesn't ship a copy of.
func ValidateRecord(recordData map[string]any) error {
	nsid, ok := recordData["$type"].(string)
	if !ok || nsid == "" {
		return fmt.Errorf("record data missing required \"$type\" field")
	}
	cat, err := Catalog()
	if err != nil {
		return err
	}
	if _, err := cat.Resolve(nsid + "#main"); err != nil {
		// No schema available locally: accept without validation.
		return nil
	}
	return indigolexicon.ValidateRecord(cat, recordData, nsid, indigolexicon.ValidateFlags(0))
}
