package shadowsocks

import (
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/zeroalloc/key"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/hkdf"
)

type udpCacheEntry struct {
	cipher    cipher.AEAD
	timestamp atomic.Int64
}

var (
	udpEncryptCache sync.Map // cacheKey -> *udpCacheEntry
	udpDecryptCache sync.Map // cacheKey -> *udpCacheEntry

	// Background cleanup
	udpCacheCleanupInterval = 5 * time.Minute
	udpCacheMaxAge          = 10 * time.Minute
)

func init() {
	// Start background cleanup goroutine
	go udpCacheCleanup()
}

func udpCacheCleanup() {
	ticker := time.NewTicker(udpCacheCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		nowNano := time.Now().UnixNano()
		maxAgeNano := udpCacheMaxAge.Nanoseconds()

		udpEncryptCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*udpCacheEntry); ok {
				if nowNano-entry.timestamp.Load() > maxAgeNano {
					udpEncryptCache.Delete(key)
				}
			}
			return true
		})

		udpDecryptCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*udpCacheEntry); ok {
				if nowNano-entry.timestamp.Load() > maxAgeNano {
					udpDecryptCache.Delete(key)
				}
			}
			return true
		})
	}
}

// generateCacheKey generates a cache key from salt and masterKey
func generateCacheKey(salt []byte, masterKey []byte) string {
	return key.ConcatKey(salt, masterKey)
}

// Optimized: EncryptUDPFromPool with cipher cache
func EncryptUDPFromPoolOptimized(key *Key, b []byte, salt []byte, reusedInfo []byte) (shadowBytes pool.PB, err error) {
	cacheKey := generateCacheKey(salt, key.MasterKey)

	// Try to get cipher from cache
	var ciph cipher.AEAD
	if cached, ok := udpEncryptCache.Load(cacheKey); ok {
		if entry, ok := cached.(*udpCacheEntry); ok {
			ciph = entry.cipher
			entry.timestamp.Store(time.Now().UnixNano())
		}
	}

	// If not in cache, create new cipher
	if ciph == nil {
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

		ciph, err = key.CipherConf.NewCipher(subKey)
		if err != nil {
			return nil, err
		}

		// Cache the cipher
		entry := &udpCacheEntry{
			cipher: ciph,
		}
		entry.timestamp.Store(time.Now().UnixNano())
		udpEncryptCache.Store(cacheKey, entry)

		// Encrypt to buf
		_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], b, nil)
		return buf, nil
	}

	// Cipher from cache, encrypt directly
	var buf = pool.Get(key.CipherConf.SaltLen + len(b) + key.CipherConf.TagLen)
	defer func() {
		if err != nil {
			pool.Put(buf)
		}
	}()
	copy(buf, salt)
	_ = ciph.Seal(buf[key.CipherConf.SaltLen:key.CipherConf.SaltLen], ciphers.ZeroNonce[:key.CipherConf.NonceLen], b, nil)
	return buf, nil
}

// Optimized: DecryptUDPFromPool with cipher cache
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

	cacheKey := generateCacheKey(shadowBytes[:key.CipherConf.SaltLen], key.MasterKey)

	var ciph cipher.AEAD
	if cached, ok := udpDecryptCache.Load(cacheKey); ok {
		if entry, ok := cached.(*udpCacheEntry); ok {
			ciph = entry.cipher
			entry.timestamp.Store(time.Now().UnixNano())
		}
	}

	if ciph == nil {
		subKey := getSubKey(key.CipherConf.KeyLen)
		defer putSubKey(subKey)

		kdf := hkdf.New(sha1.New, key.MasterKey, shadowBytes[:key.CipherConf.SaltLen], reusedInfo)

		_, err = io.ReadFull(kdf, subKey)
		if err != nil {
			return 0, err
		}

		ciph, err = key.CipherConf.NewCipher(subKey)
		if err != nil {
			return 0, err
		}

		entry := &udpCacheEntry{
			cipher: ciph,
		}
		entry.timestamp.Store(time.Now().UnixNano())
		udpDecryptCache.Store(cacheKey, entry)
	}

	writeTo, err = ciph.Open(writeTo[:0], ciphers.ZeroNonce[:key.CipherConf.NonceLen], shadowBytes[key.CipherConf.SaltLen:], nil)
	if err != nil {
		return 0, err
	}
	return len(writeTo), nil
}
