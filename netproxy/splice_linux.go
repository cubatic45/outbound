package netproxy

import (
	"io"
	"syscall"
)

// SpliceFunc performs zero-copy splice between two connections.
// This is exported for use by wrappers that need to splice after
// handling buffered data (e.g., ConnSniffer).
type SpliceFunc func(dstFD, srcFD int, limit int64) (int64, error)

// RawSplice is the low-level splice implementation, exported for
// advanced use cases. It performs zero-copy data transfer between
// two file descriptors using the splice syscall.
func RawSplice(dstFD, srcFD int, limit int64) (int64, error) {
	return splice(dstFD, srcFD, limit)
}

// SpliceTo attempts zero-copy splice from srcConn to dst.
// Returns (bytesTransferred, usedSplice, error).
// If splice is not available, it returns (0, false, nil) to indicate
// the caller should fall back to io.Copy.
func SpliceTo(dst io.Writer, srcConn interface{ SyscallConn() (syscall.RawConn, error) }) (int64, bool, error) {
	// Check if dst supports SyscallConn
	dstConn, ok := dst.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	if !ok {
		return 0, false, nil
	}

	// Get raw connections
	rawDst, err := dstConn.SyscallConn()
	if err != nil {
		return 0, false, err
	}

	rawSrc, err := srcConn.SyscallConn()
	if err != nil {
		return 0, false, err
	}

	var dstFD, srcFD int
	var errDst, errSrc error

	// Extract file descriptors
	rawDst.Control(func(fd uintptr) {
		dstFD = int(fd)
	})
	rawSrc.Control(func(fd uintptr) {
		srcFD = int(fd)
	})

	if errDst != nil || errSrc != nil {
		return 0, false, nil
	}

	// Perform zero-copy transfer
	n, err := splice(dstFD, srcFD, spliceToEOFLimit) // Transfer until EOF
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

const (
	// maxSpliceSize is the maximum size for a single splice(2) syscall.
	// Linux splice has a limit of 1GB per call; larger values may fail.
	maxSpliceSize = 1 << 30 // 1GB

	// spliceToEOFLimit is a large limit for "transfer until EOF".
	// 1TB is far larger than any realistic TCP connection will transfer,
	// so EOF will always be reached before the limit.
	spliceToEOFLimit = 1 << 40 // 1TB, effectively unlimited

	// Splice flags
	SPLICE_F_MOVE     = 0x01 // Move pages instead of copying
	SPLICE_F_NONBLOCK = 0x02 // Non-blocking operation
	SPLICE_F_MORE     = 0x04 // More data will follow
	SPLICE_F_GIFT     = 0x08 // Gift pages to kernel
)

// canSplice checks if both connections support splice operation
func canSplice(dst, src interface{}) bool {
	_, dstOk := dst.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	_, srcOk := src.(interface {
		SyscallConn() (syscall.RawConn, error)
	})
	return dstOk && srcOk
}

// splice performs zero-copy transfer from src to dst using Linux splice syscall
// Returns the number of bytes transferred and any error
func splice(dstFD, srcFD int, limit int64) (int64, error) {
	var total int64

	for total < limit {
		remaining := limit - total
		if remaining > maxSpliceSize {
			remaining = maxSpliceSize
		}

		// Use splice to transfer data directly in kernel space
		// Use SPLICE_F_MORE to indicate more data will follow
		flags := 0
		if remaining < maxSpliceSize {
			flags = SPLICE_F_MORE
		}
		n, err := syscall.Splice(srcFD, nil, dstFD, nil, int(remaining), flags)
		if err != nil {
			return total, err
		}

		total += int64(n)

		// EOF reached
		if n == 0 {
			break
		}
	}

	return total, nil
}

// ReadFrom implements io.ReaderFrom with zero-copy optimization
// This is the optimized version for Linux systems
func ReadFrom(dst Conn, src io.Reader) (int64, error) {
	// Try zero-copy splice first
	if canSplice(dst, src) {
		// Get file descriptors
		dstConn, err := dst.(interface {
			SyscallConn() (syscall.RawConn, error)
		}).SyscallConn()
		if err != nil {
			goto fallback
		}

		srcConn, err := src.(interface {
			SyscallConn() (syscall.RawConn, error)
		}).SyscallConn()
		if err != nil {
			goto fallback
		}

		var dstFD, srcFD int
		var errDst, errSrc error

		// Extract file descriptors
		dstConn.Control(func(fd uintptr) {
			dstFD = int(fd)
		})
		srcConn.Control(func(fd uintptr) {
			srcFD = int(fd)
		})

		if errDst != nil || errSrc != nil {
			goto fallback
		}

		// Perform zero-copy transfer
		n, err := splice(dstFD, srcFD, spliceToEOFLimit)
		if err == nil {
			return n, nil
		}
		// Fallback on splice errors (EINVAL for socket-to-socket, etc)
	}

fallback:
	// Standard copy fallback
	return io.Copy(dst, src)
}

// WriteTo implements io.WriterTo with zero-copy optimization
// This is the optimized version for Linux systems
func WriteTo(src Conn, dst io.Writer) (int64, error) {
	// Try zero-copy splice first
	if canSplice(dst, src) {
		dstConn, err := dst.(interface {
			SyscallConn() (syscall.RawConn, error)
		}).SyscallConn()
		if err != nil {
			goto fallback
		}

		srcConn, err := src.(interface {
			SyscallConn() (syscall.RawConn, error)
		}).SyscallConn()
		if err != nil {
			goto fallback
		}

		var dstFD, srcFD int
		var errDst, errSrc error

		dstConn.Control(func(fd uintptr) {
			dstFD = int(fd)
		})
		srcConn.Control(func(fd uintptr) {
			srcFD = int(fd)
		})

		if errDst != nil || errSrc != nil {
			goto fallback
		}

		// Perform zero-copy transfer
		n, err := splice(dstFD, srcFD, spliceToEOFLimit)
		if err == nil {
			return n, nil
		}
		// Fallback on splice errors
	}

fallback:
	// Standard copy fallback
	return io.Copy(dst, src)
}
