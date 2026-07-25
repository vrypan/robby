// Package xrpc implements the pds-light HTTP surface: XRPC endpoints,
// auth middleware, and the /.well-known/atproto-did route.
package xrpc

import (
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"

	"github.com/vrypan/pds-light/internal/actorstore"
	"github.com/vrypan/pds-light/internal/config"
	"github.com/vrypan/pds-light/internal/repoops"
	"github.com/vrypan/pds-light/internal/sequencer"
	"github.com/vrypan/pds-light/internal/store"
)

// ServiceDID is the DID used as the audience for tokens issued by this
// server and as the signer identity for service proxying. For phase 1
// (before did:web support is wired up) we derive it from the hostname.
func ServiceDID(cfg *config.Config) string {
	return "did:web:" + cfg.Hostname
}

type Server struct {
	cfg    *config.Config
	store  *store.Store
	dir    *identity.BaseDirectory
	actors *actorstore.Manager
	writer *repoops.Writer
	seq    *sequencer.Sequencer
	log    *slog.Logger
}

func NewServer(cfg *config.Config, st *store.Store, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	actors := actorstore.NewManager(cfg.DataDir)
	seq, err := sequencer.New(st.DB())
	if err != nil {
		return nil, err
	}
	writer := repoops.NewWriter(actors)
	writer.Seq = seq
	return &Server{
		cfg:   cfg,
		store: st,
		dir: &identity.BaseDirectory{
			PLCURL: cfg.PLCURL,
			// DID->pubkey lookups (service-auth validation, commit
			// signature checks during repo import) shouldn't fail just
			// because handle DNS/well-known verification hiccups; that
			// bidirectional check isn't needed for those call sites.
			SkipHandleVerification: true,
		},
		actors: actors,
		writer: writer,
		seq:    seq,
		log:    log,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /xrpc/_health", s.handleHealth)
	mux.HandleFunc("GET /.well-known/atproto-did", s.handleWellKnownDID)

	mux.HandleFunc("GET /xrpc/com.atproto.server.describeServer", s.handleDescribeServer)
	mux.HandleFunc("POST /xrpc/com.atproto.server.createSession", s.handleCreateSession)
	mux.HandleFunc("POST /xrpc/com.atproto.server.refreshSession", s.handleRefreshSession)
	mux.HandleFunc("POST /xrpc/com.atproto.server.deleteSession", s.handleDeleteSession)
	mux.HandleFunc("GET /xrpc/com.atproto.server.getSession", s.handleGetSession)
	mux.HandleFunc("GET /xrpc/com.atproto.identity.resolveHandle", s.handleResolveHandle)
	mux.HandleFunc("GET /xrpc/com.atproto.server.getServiceAuth", s.handleGetServiceAuth)
	mux.HandleFunc("POST /xrpc/com.atproto.server.createAppPassword", s.handleCreateAppPassword)
	mux.HandleFunc("GET /xrpc/com.atproto.server.listAppPasswords", s.handleListAppPasswords)
	mux.HandleFunc("POST /xrpc/com.atproto.server.revokeAppPassword", s.handleRevokeAppPassword)
	mux.HandleFunc("POST /xrpc/com.atproto.server.reserveSigningKey", s.handleReserveSigningKey)
	mux.HandleFunc("POST /xrpc/com.atproto.server.createAccount", s.handleServerCreateAccount)
	mux.HandleFunc("POST /xrpc/com.atproto.server.activateAccount", s.handleActivateAccount)
	mux.HandleFunc("POST /xrpc/com.atproto.server.deactivateAccount", s.handleDeactivateAccountSelf)
	mux.HandleFunc("POST /xrpc/com.atproto.server.deleteAccount", s.handleDeleteAccount)
	mux.HandleFunc("GET /xrpc/com.atproto.server.checkAccountStatus", s.handleCheckAccountStatus)
	mux.HandleFunc("POST /xrpc/com.atproto.identity.updateHandle", s.handleUpdateHandle)
	mux.HandleFunc("GET /xrpc/com.atproto.identity.getRecommendedDidCredentials", s.handleGetRecommendedDidCredentials)
	mux.HandleFunc("POST /xrpc/com.atproto.identity.signPlcOperation", s.handleSignPlcOperation)
	mux.HandleFunc("POST /xrpc/com.atproto.identity.submitPlcOperation", s.handleSubmitPlcOperation)

	// app.bsky.actor.{get,put}Preferences are private per-account data the
	// PDS serves directly, per the lexicon — not proxied to the AppView
	// like other app.bsky.* reads.
	mux.HandleFunc("GET /xrpc/app.bsky.actor.getPreferences", s.handleGetPreferences)
	mux.HandleFunc("POST /xrpc/app.bsky.actor.putPreferences", s.handlePutPreferences)

	mux.HandleFunc("POST /xrpc/com.atproto.repo.createRecord", s.handleCreateRecord)
	mux.HandleFunc("POST /xrpc/com.atproto.repo.putRecord", s.handlePutRecord)
	mux.HandleFunc("POST /xrpc/com.atproto.repo.deleteRecord", s.handleDeleteRecord)
	mux.HandleFunc("POST /xrpc/com.atproto.repo.applyWrites", s.handleApplyWrites)
	mux.HandleFunc("GET /xrpc/com.atproto.repo.getRecord", s.handleGetRecord)
	mux.HandleFunc("GET /xrpc/com.atproto.repo.listRecords", s.handleListRecords)
	mux.HandleFunc("GET /xrpc/com.atproto.repo.describeRepo", s.handleDescribeRepo)
	mux.HandleFunc("POST /xrpc/com.atproto.repo.uploadBlob", s.handleUploadBlob)
	mux.HandleFunc("POST /xrpc/com.atproto.repo.importRepo", s.handleImportRepo)
	mux.HandleFunc("GET /xrpc/com.atproto.repo.listMissingBlobs", s.handleListMissingBlobs)

	mux.HandleFunc("GET /xrpc/com.atproto.sync.getRepo", s.handleSyncGetRepo)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.getRepoStatus", s.handleSyncGetRepoStatus)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.getLatestCommit", s.handleSyncGetLatestCommit)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.getRecord", s.handleSyncGetRecord)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.getBlocks", s.handleSyncGetBlocks)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.listBlobs", s.handleSyncListBlobs)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.getBlob", s.handleSyncGetBlob)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.listRepos", s.handleSyncListRepos)
	mux.HandleFunc("GET /xrpc/com.atproto.sync.subscribeRepos", s.handleSubscribeRepos)

	mux.HandleFunc("POST /xrpc/com.pdslight.admin.createAccount", s.requireAdmin(s.handleAdminCreateAccount))
	mux.HandleFunc("GET /xrpc/com.pdslight.admin.listAccounts", s.requireAdmin(s.handleAdminListAccounts))
	mux.HandleFunc("POST /xrpc/com.pdslight.admin.setPassword", s.requireAdmin(s.handleAdminSetPassword))
	mux.HandleFunc("POST /xrpc/com.pdslight.admin.deactivateAccount", s.requireAdmin(s.handleAdminDeactivateAccount))
	mux.HandleFunc("POST /xrpc/com.pdslight.admin.approveToken", s.requireAdmin(s.handleAdminApproveToken))
	mux.HandleFunc("POST /xrpc/com.pdslight.admin.takedownAccount", s.requireAdmin(s.handleAdminTakedownAccount))

	// Catch-all: any /xrpc/* method not registered above (app.bsky.* reads,
	// and any other unknown NSID) is service-proxied. Go's ServeMux gives
	// exact-pattern registrations above priority over this subtree match.
	mux.HandleFunc("/xrpc/", s.handleServiceProxy)

	return withCORS(withLogging(s.log, mux))
}

// withCORS lets browser-based clients (e.g. the bsky.app web app) talk to
// the API directly. It must wrap everything, outermost: an OPTIONS
// preflight doesn't match any of our method-specific routes above, so
// without this it would otherwise fall through to the service-proxy
// catch-all and get forwarded to the AppView instead of being answered
// here.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			origin = "*"
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Atproto-Accept-Labelers, Atproto-Proxy")
		w.Header().Set("Access-Control-Expose-Headers", "Atproto-Content-Labelers, Atproto-Repo-Rev")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withLogging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"version": "pds-light/0.1.0"})
}

func (s *Server) handleWellKnownDID(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	acct, err := s.store.GetAccountByHandle(r.Context(), host)
	if err != nil {
		writeXRPCError(w, http.StatusNotFound, "NotFound", "no account for this handle")
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(acct.DID))
}
