package trojanc

import (
	"testing"
)

// BenchmarkUDPPacketOverhead 测试 UDP 包处理的内存分配
func BenchmarkUDPPacketOverhead(b *testing.B) {
	b.Run("SmallPacket", func(b *testing.B) {
		data := make([]byte, 100)
		for i := range data {
			data[i] = byte(i)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 模拟 SealUDP 分配
			_ = make([]byte, 100+4+100)
		}
	})
	
	b.Run("LargePacket", func(b *testing.B) {
		data := make([]byte, 1400)
		for i := range data {
			data[i] = byte(i)
		}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 模拟 SealUDP 分配
			_ = make([]byte, 100+4+1400)
		}
	})
}
