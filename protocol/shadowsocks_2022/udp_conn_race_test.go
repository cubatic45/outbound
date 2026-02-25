package shadowsocks_2022

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
)

func TestReplayWindowRace(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	conn := &UdpConn{
		cipherConf: conf,
		pskList:    [][]byte{psk},
		uPSK:       psk,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			sessionID := [8]byte{byte(id % 256), byte(id / 256)}
			for j := 0; j < 100; j++ {
				conn.checkAndUpdateReplay(sessionID, uint64(j), time.Now())
			}
		}(i)
	}
	wg.Wait()
}

func TestCipherCacheRace(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := GetCachedCipher(psk, sessionID, conf, true)
				if err != nil {
					t.Error(err)
				}
			}
		}()

		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := GetCachedCipher(psk, sessionID, conf, false)
				if err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}

func TestUDPCacheNoLeak(t *testing.T) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	for i := 0; i < 1000; i++ {
		sessionID := make([]byte, 8)
		sessionID[0] = byte(i % 256)
		sessionID[1] = byte(i / 256)
		_, _ = GetCachedCipher(psk, sessionID, conf, true)
	}

	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	for i := 0; i < 100000; i++ {
		sessionID := make([]byte, 8)
		_, _ = GetCachedCipher(psk, sessionID, conf, true)
	}
	runtime.GC()

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	growth := int64(m2.HeapAlloc) - int64(m1.HeapAlloc)
	if growth > 10<<20 {
		t.Errorf("Potential memory leak: heap grew by %d bytes", growth)
	}
}

func TestNoGoroutineLeak(t *testing.T) {
	before := runtime.NumGoroutine()

	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	for i := 0; i < 100; i++ {
		sessionID := make([]byte, 8)
		_, _ = GetCachedCipher(psk, sessionID, conf, true)
	}

	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	if after-before > 5 {
		t.Errorf("Potential goroutine leak: before=%d, after=%d", before, after)
	}
}

func BenchmarkCipherCacheGet(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)
	sessionID := make([]byte, 8)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetCachedCipher(psk, sessionID, conf, true)
	}
}

func BenchmarkCipherCacheGetParallel(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	b.RunParallel(func(pb *testing.PB) {
		sessionID := make([]byte, 8)
		for pb.Next() {
			_, _ = GetCachedCipher(psk, sessionID, conf, true)
		}
	})
}

func BenchmarkReplayCheck(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	psk := make([]byte, 32)

	conn := &UdpConn{
		cipherConf: conf,
		pskList:    [][]byte{psk},
		uPSK:       psk,
	}
	sessionID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.checkAndUpdateReplay(sessionID, uint64(i), now)
	}
}
