package trojanc

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

// BenchmarkNewConnOptimized 基准测试：优化后的 NewConn 性能
func BenchmarkNewConnOptimized(b *testing.B) {
	// 模拟网络连接（nil 在基准测试中可用，因为我们不实际读写）
	var mockConn netproxy.Conn
	
	metadata := Metadata{
		Metadata: protocol.Metadata{
			Hostname: "example.com",
			Port:     443,
		},
		Network: "tcp",
	}
	password := "test-password-12345"
	
	// 预热缓存
	_, _ = NewConn(mockConn, metadata, password)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		_, _ = NewConn(mockConn, metadata, password)
	}
}

// BenchmarkNewConnMultiplePasswords 基准测试：多个密码场景
func BenchmarkNewConnMultiplePasswords(b *testing.B) {
	var mockConn netproxy.Conn
	
	passwords := []string{
		"password1",
		"password2",
		"password3",
		"password4", 
		"password5",
	}
	
	metadata := Metadata{
		Metadata: protocol.Metadata{
			Hostname: "example.com",
			Port:     443,
		},
		Network: "tcp",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		password := passwords[i%len(passwords)]
		_, _ = NewConn(mockConn, metadata, password)
	}
}

// TestPasswordHashConsistency 测试密码哈希一致性
func TestPasswordHashConsistency(t *testing.T) {
	password := "test-password"
	
	// 第一次获取（计算）
	hash1 := getPasswordHash(password)
	
	// 第二次获取（缓存）
	hash2 := getPasswordHash(password)
	
	// 验证一致性
	if hash1 != hash2 {
		t.Errorf("password hash inconsistency")
	}
}

// TestPasswordHashCorrectness 测试密码哈希正确性
func TestPasswordHashCorrectness(t *testing.T) {
	password := "test-password"
	
	// 使用新函数计算
	hash := getPasswordHash(password)
	
	// 手动计算预期值
	expected := [56]byte{}
	h := sha256.New224()
	h.Write([]byte(password))
	hex.Encode(expected[:], h.Sum(nil))
	
	// 验证正确性
	if hash != expected {
		t.Errorf("password hash incorrect")
	}
}
