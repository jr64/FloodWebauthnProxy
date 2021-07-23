package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {

	if d == nil {
		d = "An unexpected error occured"
	}

	switch d.(type) {
	case string:
		m := make(map[string]string, 1)
		m["message"] = d.(string)
		d = m
	}
	dj, err := json.Marshal(d)
	if err != nil {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	fmt.Fprintf(w, "%s", dj)
}
