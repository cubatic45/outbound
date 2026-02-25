package shadowsocks_2022

import (
	"crypto/cipher"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/zeroalloc/key"
)

type cipherCacheEntry struct {
	cipher    cipher.AEAD
	timestamp atomic.Int64
}

var (
	udpEncryptCache sync.Map
	udpDecryptCache sync.Map

	udpCacheCleanupInterval = 5 * time.Minute
	udpCacheMaxAge          = 10 * time.Minute
)

func init() {
	go udpCacheCleanup()
}

func udpCacheCleanup() {
	ticker := time.NewTicker(udpCacheCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		nowNano := time.Now().UnixNano()
		maxAgeNano := udpCacheMaxAge.Nanoseconds()

		udpEncryptCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*cipherCacheEntry); ok {
				if nowNano-entry.timestamp.Load() > maxAgeNano {
					udpEncryptCache.Delete(key)
				}
			}
			return true
		})

		udpDecryptCache.Range(func(key, value interface{}) bool {
			if entry, ok := value.(*cipherCacheEntry); ok {
				if nowNano-entry.timestamp.Load() > maxAgeNano {
					udpDecryptCache.Delete(key)
				}
			}
			return true
		})
	}
}

func generateCacheKey(sessionID []byte, psk []byte) string {
	pskPart := psk
	if len(psk) > 8 {
		pskPart = psk[:8]
	}
	return key.ConcatKey(sessionID, pskPart)
}

func GetCachedCipher(psk []byte, sessionID []byte, cipherConf *ciphers.CipherConf2022, isEncrypt bool) (cipher.AEAD, error) {
	cacheKey := generateCacheKey(sessionID, psk)

	cache := &udpDecryptCache
	if isEncrypt {
		cache = &udpEncryptCache
	}

	if cached, ok := cache.Load(cacheKey); ok {
		if entry, ok := cached.(*cipherCacheEntry); ok {
			entry.timestamp.Store(time.Now().UnixNano())
			return entry.cipher, nil
		}
	}

	ciph, err := CreateCipher(psk, sessionID, cipherConf)
	if err != nil {
		return nil, err
	}

	entry := &cipherCacheEntry{
		cipher: ciph,
	}
	entry.timestamp.Store(time.Now().UnixNano())
	cache.Store(cacheKey, entry)

	return ciph, nil
}
