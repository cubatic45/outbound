package netproxy

import (
	"errors"
	"io"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// SpliceFunc performs zero-copy splice between two connections.
// This is exported for use by wrappers that need to splice after
// handling buffered data (e.g., ConnSniffer).
type SpliceFunc func(dstFD, srcFD int, limit int64) (int64, error)

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

// RawSplice is the low-level splice implementation, exported for
// advanced use cases. It performs zero-copy data transfer between
// two file descriptors using the splice syscall.
func RawSplice(dstFD, srcFD int, limit int64) (int64, error) {
	return spliceDirect(dstFD, srcFD, limit)
}

// SpliceTo attempts zero-copy splice from srcConn to dst.
// Returns (bytesTransferred, usedSplice, error).
// If splice is not available, it returns (0, false, nil) to indicate
// the caller should fall back to io.Copy.
func SpliceTo(dst io.Writer, srcConn interface {
	SyscallConn() (syscall.RawConn, error)
}) (int64, bool, error) {
	dstFD, srcFD, ok, err := spliceFDs(dst, srcConn)
	if !ok {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}

	return spliceFDToEOF(dstFD, srcFD)
}

func spliceFDs(dst io.Writer, src syscallConn) (dstFD int, srcFD int, ok bool, err error) {
	dstConn, ok := dst.(syscallConn)
	if !ok {
		return 0, 0, false, nil
	}
	dstFD, err = fdFromConn(dstConn)
	if err != nil {
		return 0, 0, false, err
	}
	srcFD, err = fdFromConn(src)
	if err != nil {
		return 0, 0, false, err
	}
	return dstFD, srcFD, true, nil
}

func spliceFDToEOF(dstFD, srcFD int) (int64, bool, error) {
	n, err := spliceDirect(dstFD, srcFD, spliceToEOFLimit)
	if err == nil {
		return n, true, nil
	}
	total := n

	n, err = spliceViaPipe(dstFD, srcFD, spliceToEOFLimit)
	total += n
	if err == nil {
		return total, true, nil
	}
	if total > 0 {
		return total, true, err
	}
	return 0, false, err
}

const (
	// maxSpliceSize is the maximum size for a single splice(2) syscall.
	// Linux splice has a limit of 1GB per call; larger values may fail.
	maxSpliceSize = 1 << 30 // 1GB

	// spliceToEOFLimit is a large limit for "transfer until EOF".
	// 1TB is far larger than any realistic TCP connection will transfer,
	// so EOF will always be reached before the limit.
	spliceToEOFLimit = 1 << 40 // 1TB, effectively unlimited

	// splicePipeChunkSize controls each kernel splice call when using pipe relay.
	splicePipeChunkSize = 1 << 20 // 1MB

	// Splice flags
	SPLICE_F_MOVE     = 0x01 // Move pages instead of copying
	SPLICE_F_NONBLOCK = 0x02 // Non-blocking operation
	SPLICE_F_MORE     = 0x04 // More data will follow
	SPLICE_F_GIFT     = 0x08 // Gift pages to kernel
)

// canSplice checks if both connections support splice operation
func canSplice(dst, src interface{}) bool {
	_, dstOk := dst.(syscallConn)
	_, srcOk := src.(syscallConn)
	return dstOk && srcOk
}

// splice keeps historical behavior for callers/tests: direct splice only.
func splice(dstFD, srcFD int, limit int64) (int64, error) {
	return spliceDirect(dstFD, srcFD, limit)
}

// spliceDirect performs direct srcFD->dstFD splice calls.
func spliceDirect(dstFD, srcFD int, limit int64) (int64, error) {
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

// spliceViaPipe performs robust socket->pipe->socket relay using splice.
func spliceViaPipe(dstFD, srcFD int, limit int64) (int64, error) {
	pipeFD := make([]int, 2)
	if err := unix.Pipe2(pipeFD, unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	defer unix.Close(pipeFD[0])
	defer unix.Close(pipeFD[1])

	var total int64
	for total < limit {
		remaining := limit - total
		if remaining > splicePipeChunkSize {
			remaining = splicePipeChunkSize
		}

		var in int64
		var err error
		for {
			in, err = spliceCount(srcFD, pipeFD[1], int(remaining))
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				runtime.Gosched()
				continue
			}
			if err != nil {
				return total, err
			}
			break
		}
		if in == 0 {
			return total, nil
		}

		left := int(in)
		for left > 0 {
			var out int64
			for {
				out, err = spliceCount(pipeFD[0], dstFD, left)
				if errors.Is(err, unix.EINTR) {
					continue
				}
				if errors.Is(err, unix.EAGAIN) {
					runtime.Gosched()
					continue
				}
				if err != nil {
					// src->pipe already consumed bytes from src and cannot be replayed via fallback.
					return total + (in - int64(left)), err
				}
				break
			}
			if out == 0 {
				return total + (in - int64(left)), io.ErrNoProgress
			}
			left -= int(out)
		}
		total += in
	}
	return total, nil
}

func fdFromConn(c syscallConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var fd int
	if err := raw.Control(func(u uintptr) { fd = int(u) }); err != nil {
		return 0, err
	}
	return fd, nil
}

// ReadFrom implements io.ReaderFrom with zero-copy optimization
// This is the optimized version for Linux systems
func ReadFrom(dst Conn, src io.Reader) (int64, error) {
	if srcConn, ok := src.(syscallConn); ok {
		if n, usedSplice, err := SpliceTo(dst, srcConn); usedSplice {
			return n, err
		}
	}
	return io.Copy(dst, src)
}

// WriteTo implements io.WriterTo with zero-copy optimization
// This is the optimized version for Linux systems
func WriteTo(src Conn, dst io.Writer) (int64, error) {
	if srcConn, ok := src.(syscallConn); ok {
		if n, usedSplice, err := SpliceTo(dst, srcConn); usedSplice {
			return n, err
		}
	}
	return io.Copy(dst, src)
}
