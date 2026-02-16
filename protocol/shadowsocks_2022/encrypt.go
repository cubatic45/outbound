package shadowsocks_2022

import (
	"crypto/cipher"

	"github.com/daeuniverse/outbound/ciphers"
	"lukechampine.com/blake3"
)

var (
	Shadowsocks2022ReusedInfo         = "shadowsocks 2022 session subkey"
	Shadowsocks2022IdentityHeaderInfo = "shadowsocks 2022 identity subkey"
)

func GenerateSubKey(psk []byte, salt []byte, context string) (subKey []byte) {
	subKey = make([]byte, len(psk))
	keyMaterial := make([]byte, 0, len(psk)+len(salt))
	keyMaterial = append(keyMaterial, psk...)
	keyMaterial = append(keyMaterial, salt...)
	blake3.DeriveKey(subKey, context, keyMaterial)
	return
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	subKey := GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo)
	return cipherConf.NewCipher(subKey)
}
