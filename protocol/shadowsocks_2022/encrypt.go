package shadowsocks_2022

import (
	"crypto/cipher"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
	"lukechampine.com/blake3"
)

var (
	Shadowsocks2022ReusedInfo         = "shadowsocks 2022 session subkey"
	Shadowsocks2022IdentityHeaderInfo = "shadowsocks 2022 identity subkey"
)

func GenerateSubKey(psk []byte, salt []byte, context string) (subKey []byte) {
	subKey = pool.Get(len(psk))
	keyMaterial := pool.GetBuffer()
	defer pool.PutBuffer(keyMaterial)
	keyMaterial.Write(psk)
	keyMaterial.Write(salt)
	blake3.DeriveKey(subKey, context, keyMaterial.Bytes())
	return
}

func CreateCipher(masterKey []byte, salt []byte, cipherConf *ciphers.CipherConf2022) (cipher cipher.AEAD, err error) {
	subKey := GenerateSubKey(masterKey, salt, Shadowsocks2022ReusedInfo)
	return cipherConf.NewCipher(subKey)
}
