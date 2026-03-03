package netproxy

import (
	"bytes"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
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

func unixConnPair(tb testing.TB) (*net.UnixConn, *net.UnixConn) {
	tb.Helper()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		tb.Fatal(err)
	}

	f0 := os.NewFile(uintptr(fds[0]), "pair-0")
	f1 := os.NewFile(uintptr(fds[1]), "pair-1")
	defer f0.Close()
	defer f1.Close()

	c0raw, err := net.FileConn(f0)
	if err != nil {
		tb.Fatal(err)
	}
	c1raw, err := net.FileConn(f1)
	if err != nil {
		_ = c0raw.Close()
		tb.Fatal(err)
	}

	c0, ok := c0raw.(*net.UnixConn)
	if !ok {
		_ = c0raw.Close()
		_ = c1raw.Close()
		tb.Fatal("endpoint 0 is not UnixConn")
	}
	c1, ok := c1raw.(*net.UnixConn)
	if !ok {
		_ = c0raw.Close()
		_ = c1raw.Close()
		tb.Fatal("endpoint 1 is not UnixConn")
	}
	return c0, c1
}

func TestReadFromLinuxSplicePath(t *testing.T) {
	srcWriter, srcRelay := unixConnPair(t)
	dstRelay, dstReader := unixConnPair(t)
	defer srcWriter.Close()
	defer srcRelay.Close()
	defer dstRelay.Close()
	defer dstReader.Close()

	payload := bytes.Repeat([]byte{0x42}, 256*1024)
	var received bytes.Buffer

	var wg sync.WaitGroup
	wg.Add(2)

	writeErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := srcWriter.Write(payload)
		if err == nil {
			err = srcWriter.CloseWrite()
		}
		writeErrCh <- err
	}()

	readErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&received, dstReader)
		readErrCh <- err
	}()

	n, err := ReadFrom(dstRelay, srcRelay)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("ReadFrom bytes mismatch: got %d want %d", n, len(payload))
	}

	_ = dstRelay.CloseWrite()
	wg.Wait()

	if err := <-writeErrCh; err != nil {
		t.Fatalf("writer failed: %v", err)
	}
	if err := <-readErrCh; err != nil {
		t.Fatalf("reader failed: %v", err)
	}
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatal("payload mismatch after ReadFrom relay")
	}
}

func TestWriteToLinuxSplicePath(t *testing.T) {
	srcWriter, srcRelay := unixConnPair(t)
	dstRelay, dstReader := unixConnPair(t)
	defer srcWriter.Close()
	defer srcRelay.Close()
	defer dstRelay.Close()
	defer dstReader.Close()

	payload := bytes.Repeat([]byte{0x7a}, 256*1024)
	var received bytes.Buffer

	var wg sync.WaitGroup
	wg.Add(2)

	writeErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := srcWriter.Write(payload)
		if err == nil {
			err = srcWriter.CloseWrite()
		}
		writeErrCh <- err
	}()

	readErrCh := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, err := io.Copy(&received, dstReader)
		readErrCh <- err
	}()

	n, err := WriteTo(srcRelay, dstRelay)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if n != int64(len(payload)) {
		t.Fatalf("WriteTo bytes mismatch: got %d want %d", n, len(payload))
	}

	_ = dstRelay.CloseWrite()
	wg.Wait()

	if err := <-writeErrCh; err != nil {
		t.Fatalf("writer failed: %v", err)
	}
	if err := <-readErrCh; err != nil {
		t.Fatalf("reader failed: %v", err)
	}
	if !bytes.Equal(received.Bytes(), payload) {
		t.Fatal("payload mismatch after WriteTo relay")
	}
}
