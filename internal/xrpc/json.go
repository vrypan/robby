package xrpc

import (
	"encoding/json"
	"fmt"
	"io"
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

const maxJSONBodyBytes = 1 << 20

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxJSONBodyBytes+1))
	if err := decoder.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("unexpected trailing JSON value")
	}
	return nil
}
