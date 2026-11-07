package web

import (
	"log"
	"net/http"
	"strings"

	"github.com/bolkedebruin/rdpgw/cmd/auth/ntlm"
	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
	"github.com/bolkedebruin/rdpgw/shared/auth"
)

// TokenNTLM runs NTLM in process against credentials derived from issued PAA tokens. The
// token then goes through the gateway's usual check at tunnel creation.
type TokenNTLM struct {
	Auth  *ntlm.NTLMAuth
	Token func(username string) (string, bool)
}

func (t *TokenNTLM) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scheme, payload, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || payload == "" {
			challengeNTLM(w, "NTLM")
			return
		}
		res, err := t.Auth.Authenticate(&auth.NtlmRequest{Session: r.RemoteAddr, NtlmMessage: payload})
		if err != nil {
			log.Printf("gateway token NTLM failed: %s", err)
			challengeNTLM(w, "NTLM")
			return
		}
		if res.NtlmMessage != "" {
			challengeNTLM(w, scheme+" "+res.NtlmMessage)
			return
		}
		token, known := t.Token(res.Username)
		if !res.Authenticated || !known {
			log.Printf("gateway token NTLM rejected for %s", res.Username)
			challengeNTLM(w, "NTLM")
			return
		}
		log.Printf("gateway token NTLM accepted for %s", res.Username)
		id := identity.FromRequestCtx(r)
		id.SetAttribute(identity.AttrGatewayToken, token)
		next.ServeHTTP(w, identity.AddToRequestCtx(id, r))
	}
}

func challengeNTLM(w http.ResponseWriter, value string) {
	w.Header().Add("WWW-Authenticate", value)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// LogGatewayRequest records how a client approached the gateway, without its credentials.
func LogGatewayRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
		log.Printf("gateway request: %s %s auth=%q upgrade=%q agent=%q", r.Method, r.URL.Path, scheme, r.Header.Get("Upgrade"), r.Header.Get("User-Agent"))
		next.ServeHTTP(w, r)
	})
}
