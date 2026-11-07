package security

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/patrickmn/go-cache"
)

// Issued tokens, held only for as long as they could still be used. NTLM needs the
// password on this side, and keeping it here confines tokens to the issuing instance.
var gatewayTokens = cache.New(6*time.Minute, time.Minute)

type gatewayToken struct{ token, password string }

func gatewayHash(label, token string) string {
	sum := sha256.Sum256([]byte(label + "\x00" + token))
	return hex.EncodeToString(sum[:])
}

// rememberGatewayToken stores a token under the credentials a client derives from it. The
// fixed lengths keep them clear of password limits, which differ between Windows versions.
func rememberGatewayToken(token string) {
	user := gatewayHash("usbgw-user", token)[:32]
	gatewayTokens.SetDefault(user, gatewayToken{token, gatewayHash("usbgw-pass", token)})
}

// GatewayTokenForUser returns the token behind a derived username.
func GatewayTokenForUser(username string) (string, bool) {
	if v, found := gatewayTokens.Get(username); found {
		return v.(gatewayToken).token, true
	}
	return "", false
}

// GatewayTokenUsers gives the NTLM code the derived passwords.
type GatewayTokenUsers struct{}

func (GatewayTokenUsers) GetPassword(username string) string {
	if v, found := gatewayTokens.Get(username); found {
		return v.(gatewayToken).password
	}
	return ""
}
