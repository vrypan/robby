package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// version is optionally stamped at build time:
//
//	go build -ldflags "-X main.version=v1.2.3"
//
// (the Makefile does this). Leaving it empty is the normal case:
// `go install ...@v1.2.3` records the version in the build info, and a
// plain `go build` in a git checkout gets the commit from the VCS stamps
// Go adds automatically.
var version = ""

// Version reports the running version: the stamped value, else the module
// version, else the commit it was built from.
func Version() string {
	if version != "" {
		return version
	}

	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	// Set when installed with `go install module@version`. A local build
	// reports "(devel)", which tells the user nothing.
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	var revision, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
			if len(revision) > 12 {
				revision = revision[:12]
			}
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if revision == "" {
		return "devel"
	}
	return "devel-" + revision + dirty
}

// VersionString is what --version prints. The Go version and platform are
// worth having in a bug report.
func VersionString() string {
	return fmt.Sprintf("robby %s\n%s %s/%s",
		Version(), runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
