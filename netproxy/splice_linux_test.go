package netproxy

import (
	"io"
	"syscall"
	"testing"
)

type mockSyscallConn struct {
	fd int
}

func (m *mockSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return &mockRawConn{fd: m.fd}, nil
}

type mockRawConn struct {
	fd int
}

func (m *mockRawConn) Control(f func(fd uintptr)) error {
	f(uintptr(m.fd))
	return nil
}

func (m *mockRawConn) Read(f func(fd uintptr) (done bool)) error {
	return nil
}

func (m *mockRawConn) Write(f func(fd uintptr) (done bool)) error {
	return nil
}

func TestCanSpliceCheck(t *testing.T) {
	conn := &mockSyscallConn{fd: 1}
	if !canSplice(conn, conn) {
		t.Error("canSplice should return true for mockSyscallConn")
	}

	var r io.Reader
	if canSplice(conn, r) {
		t.Error("canSplice should return false for non-syscallConn")
	}
}

func TestCanSpliceWithNil(t *testing.T) {
	if canSplice(nil, nil) {
		t.Error("canSplice should return false for nil")
	}
}
