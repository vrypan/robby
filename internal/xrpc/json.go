package xrpc

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeXRPCError writes a response in the standard XRPC error shape:
// {"error": "<Name>", "message": "<message>"}.
func writeXRPCError(w http.ResponseWriter, status int, name, message string) {
	writeJSON(w, status, map[string]string{"error": name, "message": message})
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
