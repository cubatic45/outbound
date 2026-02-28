//go:build !linux
// +build !linux

package netproxy

import (
	"io"
	"syscall"
)

// ReadFrom implements io.ReaderFrom with standard copy for non-Linux systems
func ReadFrom(dst Conn, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}

// WriteTo implements io.WriterTo with standard copy for non-Linux systems
func WriteTo(src Conn, dst io.Writer) (int64, error) {
	return io.Copy(dst, src)
}

// RawSplice is a no-op on non-Linux systems.
func RawSplice(dstFD, srcFD int, limit int64) (int64, error) {
	return 0, syscall.ENOSYS
}

// SpliceTo always indicates splice is unavailable on non-Linux systems.
func SpliceTo(dst io.Writer, srcConn interface{ SyscallConn() (syscall.RawConn, error) }) (int64, bool, error) {
	return 0, false, nil
}
