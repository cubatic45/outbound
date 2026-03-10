package shadowsocks_2022

import (
	"crypto/cipher"

	"github.com/daeuniverse/outbound/ciphers"
)

// GetCachedCipher creates a new AEAD cipher for the given PSK and session ID.
// Note: Caching was removed because UDP connections typically have unique session IDs,
// making cache hits rare. Direct creation is simpler and has no performance penalty.
func GetCachedCipher(psk []byte, sessionID []byte, cipherConf *ciphers.CipherConf2022, isEncrypt bool) (cipher.AEAD, error) {
	return CreateCipher(psk, sessionID, cipherConf)
}