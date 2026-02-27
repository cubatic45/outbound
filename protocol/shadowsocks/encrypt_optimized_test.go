/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@daeuniverse.org>
 */

package shadowsocks

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/daeuniverse/outbound/ciphers"
)

// TestEncryptDecryptCompatibility tests that optimized version produces same results
func TestEncryptDecryptCompatibility(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	rand.Read(masterKey)

	salt := make([]byte, conf.SaltLen)
	rand.Read(salt)

	plaintext := []byte("Hello, World! This is a test message for Shadowsocks encryption.")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	// Test original version
	encrypted1, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatalf("EncryptUDPFromPool failed: %v", err)
	}
	defer encrypted1.Put()

	decrypted1, err := DecryptUDPFromPool(key, encrypted1, reusedInfo)
	if err != nil {
		t.Fatalf("DecryptUDPFromPool failed: %v", err)
	}
	defer decrypted1.Put()

	// Test optimized version
	encrypted2, err := EncryptUDPFromPoolOptimized(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatalf("EncryptUDPFromPoolOptimized failed: %v", err)
	}
	defer encrypted2.Put()

	decrypted2, err := DecryptUDPFromPoolOptimized(key, encrypted2, reusedInfo)
	if err != nil {
		t.Fatalf("DecryptUDPFromPoolOptimized failed: %v", err)
	}
	defer decrypted2.Put()

	// Compare results
	if !bytes.Equal(encrypted1, encrypted2) {
		t.Errorf("Encrypted results differ:\n  original:  %x\n  optimized: %x", encrypted1, encrypted2)
	}

	if !bytes.Equal(decrypted1, decrypted2) {
		t.Errorf("Decrypted results differ:\n  original:  %x\n  optimized: %x", decrypted1, decrypted2)
	}

	if !bytes.Equal(decrypted1, plaintext) {
		t.Errorf("Decrypted text doesn't match plaintext:\n  decrypted: %x\n  plaintext: %x", decrypted1, plaintext)
	}
}

// TestCrossCompatibility tests that original and optimized versions can decrypt each other
func TestCrossCompatibility(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	rand.Read(masterKey)

	salt := make([]byte, conf.SaltLen)
	rand.Read(salt)

	plaintext := []byte("Cross compatibility test message")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	// Encrypt with original, decrypt with optimized
	encrypted1, err := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted1.Put()

	decrypted1, err := DecryptUDPFromPoolOptimized(key, encrypted1, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted1.Put()

	if !bytes.Equal(decrypted1, plaintext) {
		t.Errorf("Original -> Optimized failed")
	}

	// Encrypt with optimized, decrypt with original
	encrypted2, err := EncryptUDPFromPoolOptimized(key, plaintext, salt, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer encrypted2.Put()

	decrypted2, err := DecryptUDPFromPool(key, encrypted2, reusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer decrypted2.Put()

	if !bytes.Equal(decrypted2, plaintext) {
		t.Errorf("Optimized -> Original failed")
	}
}

// TestMultipleSalts verifies correct behavior with different salts
func TestMultipleSalts(t *testing.T) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	rand.Read(masterKey)

	plaintext := []byte("Multi-salt test")
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	for i := 0; i < 10; i++ {
		salt := make([]byte, conf.SaltLen)
		rand.Read(salt)

		encrypted, err := EncryptUDPFromPoolOptimized(key, plaintext, salt, reusedInfo)
		if err != nil {
			t.Fatalf("Encrypt iteration %d failed: %v", i, err)
		}

		decrypted, err := DecryptUDPFromPoolOptimized(key, encrypted, reusedInfo)
		if err != nil {
			encrypted.Put()
			t.Fatalf("Decrypt iteration %d failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("Salt %d failed", i)
		}

		encrypted.Put()
		decrypted.Put()
	}
}

// Benchmark comparison
func BenchmarkEncryptOriginal(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		shadowBytes.Put()
	}
}

func BenchmarkEncryptOptimized(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		shadowBytes, _ := EncryptUDPFromPoolOptimized(key, plaintext, salt, reusedInfo)
		shadowBytes.Put()
	}
}

func BenchmarkDecryptOriginal(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	shadowBytes, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
	defer shadowBytes.Put()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ := DecryptUDPFromPool(key, shadowBytes, reusedInfo)
		buf.Put()
	}
}

func BenchmarkDecryptOptimized(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	salt := make([]byte, conf.SaltLen)
	plaintext := make([]byte, 1024)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	shadowBytes, _ := EncryptUDPFromPoolOptimized(key, plaintext, salt, reusedInfo)
	defer shadowBytes.Put()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, _ := DecryptUDPFromPoolOptimized(key, shadowBytes, reusedInfo)
		buf.Put()
	}
}

// Benchmark real-world scenario: UDP packets with different salts
func BenchmarkRealWorld_Original(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	plaintext := make([]byte, 512)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		salt := make([]byte, conf.SaltLen)
		rand.Read(salt)
		encrypted, _ := EncryptUDPFromPool(key, plaintext, salt, reusedInfo)
		decrypted, _ := DecryptUDPFromPool(key, encrypted, reusedInfo)
		encrypted.Put()
		decrypted.Put()
	}
}

func BenchmarkRealWorld_Optimized(b *testing.B) {
	conf := ciphers.AeadCiphersConf["aes-256-gcm"]
	masterKey := make([]byte, conf.KeyLen)
	plaintext := make([]byte, 512)
	reusedInfo := []byte("ss-subkey")

	key := &Key{
		CipherConf: conf,
		MasterKey:  masterKey,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		salt := make([]byte, conf.SaltLen)
		rand.Read(salt)
		encrypted, _ := EncryptUDPFromPoolOptimized(key, plaintext, salt, reusedInfo)
		decrypted, _ := DecryptUDPFromPoolOptimized(key, encrypted, reusedInfo)
		encrypted.Put()
		decrypted.Put()
	}
}
