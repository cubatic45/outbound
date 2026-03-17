// modified from https://github.com/nadoo/glider/blob/master/pool/buffer.go

package pool

import (
	"math/bits"
	"sync"
)

const (
	// number of pools.
	num          = 17
	maxsize      = 1 << (num - 1)
	minsizePower = 6
	minsize      = 1 << minsizePower
)

var (
	pools [num]sync.Pool
)

func init() {
	for i := minsizePower; i < num; i++ {
		size := 1 << i
		pools[i].New = func() interface{} {
			return make([]byte, size)
		}
	}
}

func GetClosestN(need int) (n int) {
	// if need is exactly 2^n, return n-1
	if need&(need-1) == 0 {
		return bits.Len32(uint32(need)) - 1
	}
	// or return its closest n
	return bits.Len32(uint32(need))
}

func GetBiggerClosestN(need int) (n int) {
	// or return its closest n
	return bits.Len32(uint32(need))
}

// Get gets a buffer from pool, size should in range: [1, 65536],
// otherwise, this function will call make([]byte, size) directly.
func Get(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetClosestN(size)
		if i < minsizePower {
			i = minsizePower
		}
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

func GetFullCap(size int) PB {
	a := Get(size)
	a = a[:cap(a)]
	return a
}

func GetMustBigger(size int) PB {
	if size >= 1 && size <= maxsize {
		i := GetBiggerClosestN(size)
		if i < minsizePower {
			i = minsizePower
		}
		return pools[i].Get().([]byte)[:size]
	}
	return make([]byte, size)
}

func GetZero(size int) []byte {
	b := Get(size)
	for i := range b {
		b[i] = 0
	}
	return b
}

func Put(buf []byte) {
	size := cap(buf)
	if size < minsize || size > maxsize {
		// Strictly avoid returning oversize huge buffers to prevent memory leak/retention.
		// Small buffers are also directly discarded.
		return
	}
	
	// For non-power-of-2 sizes, use GetBiggerClosestN to round up to the next bucket.
	// This ensures capacity is not wasted and buffers go to the correct bucket.
	// Examples:
	//   - size=1536 -> i=11 (bucket for 2048) instead of 10 (bucket for 1024)
	//   - size=1024 -> i=10 (bucket for 1024)
	i := GetBiggerClosestN(size)
	if i < minsizePower {
		i = minsizePower
	}
	if i < num {
		pools[i].Put(buf)
	}
}
