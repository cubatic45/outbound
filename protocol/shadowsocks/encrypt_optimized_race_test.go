package shadowsocks

import (
	"sync"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pool"
)

func TestUDPCacheRace(t *testing.T) {
	key := &Key{
		CipherConf: ciphers.AeadCiphersConf["aes-256-gcm"],
		MasterKey:  make([]byte, 32),
	}
	salt := make([]byte, key.CipherConf.SaltLen)
	data := make([]byte, 1024)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				encrypted, err := EncryptUDPFromPoolOptimized(key, data, salt, nil)
				if err != nil {
					t.Error(err)
					return
				}
				pool.Put(encrypted)
			}
		}()

		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				encrypted, _ := EncryptUDPFromPoolOptimized(key, data, salt, nil)
				decrypted := make([]byte, len(data)+32)
				_, err := DecryptUDPOptimized(decrypted[:0], key, encrypted, nil)
				if err != nil {
					t.Error(err)
				}
				pool.Put(encrypted)
			}
		}()
	}
	wg.Wait()
}

func TestCacheKeyRace(t *testing.T) {
	salt := make([]byte, 16)
	key := make([]byte, 32)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = generateCacheKey(salt, key)
			}
		}()
	}
	wg.Wait()
}

func TestCalcPaddingLenRace(t *testing.T) {
	masterKey := make([]byte, 32)
	body := make([]byte, 1024)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = CalcPaddingLen(masterKey, body, true)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				_ = CalcPaddingLen(masterKey, body, false)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkCalcPaddingLen(b *testing.B) {
	masterKey := make([]byte, 32)
	body := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CalcPaddingLen(masterKey, body, true)
	}
}

func BenchmarkCalcPaddingLenParallel(b *testing.B) {
	masterKey := make([]byte, 32)
	body := make([]byte, 1024)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = CalcPaddingLen(masterKey, body, true)
		}
	})
}
