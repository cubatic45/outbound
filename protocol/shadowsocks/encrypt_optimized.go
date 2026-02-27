package shadowsocks

import (
	"crypto/sha1"
	"fmt"
	"io"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/zeroalloc/key"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

func generateCacheKey(salt []byte, masterKey []byte) string {
	return key.ConcatKey(salt, masterKey)
}

func EncryptUDPFromPoolOptimized(key *Key, b []byte, salt []byte, reusedInfo []byte) (shadowBytes pool.PB, err error) {
	var buf = pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()
	copy(buf, salt)
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)
	kdf := hkdf.New(sha1.New, key.MasterKey, buf[:key.CipherConf.SaltLen], reusedInfo)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return nil, err
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return nil, err
	}
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

func DecryptUDPFromPoolOptimized(key *Key, shadowBytes []byte, reusedInfo []byte) (buf pool.PB, err error) {
	buf = pool.Get(len(shadowBytes))
	n, err := DecryptUDPOptimized(buf[:0], key, shadowBytes, reusedInfo)
	if err != nil {
		buf.Put()
		return nil, err
	}
	return buf[:n], nil
}

func DecryptUDPOptimized(writeTo []byte, key *Key, shadowBytes []byte, reusedInfo []byte) (n int, err error) {
	if len(shadowBytes) < key.CipherConf.SaltLen {
		return 0, fmt.Errorf("short length to decrypt")
	}
	subKey := getSubKey(key.CipherConf.KeyLen)
	defer putSubKey(subKey)
	kdf := hkdf.New(sha1.New, key.MasterKey, shadowBytes[:key.CipherConf.SaltLen], reusedInfo)
	_, err = io.ReadFull(kdf, subKey)
	if err != nil {
		return 0, err
	}
	ciph, err := key.CipherConf.NewCipher(subKey)
	if err != nil {
		return 0, err
	}
	writeTo, err = ciph.Open(writeTo[:0], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return 0, err
	}
	return len(writeTo), nil
}
