package api

import (
	"encoding/json"
	"net/http"
)

// respond writes a JSON response with the given status code.
func respond(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// parseJSON decodes JSON from the request body into v.
func parseJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// errOut writes an error response with the given status code and message.
func errOut(w http.ResponseWriter, code int, msg string) {
	respond(w, code, map[string]string{"error": msg})
}

// sanitizeID converts a name into a valid ID string.
func sanitizeID(name string) string {
	r := strings.NewReplacer(" ", "_", "/", "_", ".", "_", "-", "_")
	id := strings.ToLower(r.Replace(strings.TrimSpace(name)))
	for strings.Contains(id, "__") {
		id = strings.ReplaceAll(id, "__", "_")
	}
	return strings.Trim(id, "_")
}

// safeSlice returns a truncated string up to n characters, or the full string if shorter.
func safeSlice(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
