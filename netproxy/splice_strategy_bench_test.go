//go:build linux
// +build linux

package netproxy

import (
	"bytes"
	"io"
	"syscall"
	"testing"
)

func legacyReadFrom(dst Conn, src io.Reader) (int64, error) {
	if canSplice(dst, src) {
		dstFD, err := fdFromConn(dst.(interface {
			SyscallConn() (syscall.RawConn, error)
		}))
		if err == nil {
			srcFD, err := fdFromConn(src.(interface {
				SyscallConn() (syscall.RawConn, error)
			}))
			if err == nil {
				n, serr := spliceDirect(dstFD, srcFD, spliceToEOFLimit)
				if serr == nil {
					return n, nil
				}
			}
		}
	}
	return io.Copy(dst, src)
}

func legacyWriteTo(src Conn, dst io.Writer) (int64, error) {
	if canSplice(dst, src) {
		dstFD, err := fdFromConn(dst.(interface {
			SyscallConn() (syscall.RawConn, error)
		}))
		if err == nil {
			srcFD, err := fdFromConn(src.(interface {
				SyscallConn() (syscall.RawConn, error)
			}))
			if err == nil {
				n, serr := spliceDirect(dstFD, srcFD, spliceToEOFLimit)
				if serr == nil {
					return n, nil
				}
			}
		}
	}
	return io.Copy(dst, src)
}

func benchmarkRelayPath(b *testing.B, payload []byte, fn func(dst Conn, src io.Reader) (int64, error)) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		writeErrCh := make(chan error, 1)
		go func() {
			_, err := srcWriter.Write(payload)
			if err == nil {
				err = srcWriter.CloseWrite()
			}
			writeErrCh <- err
		}()

		drainErrCh := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, dstReader)
			drainErrCh <- err
		}()

		n, err := fn(dstRelay, srcRelay)
		if err != nil {
			b.Fatalf("relay failed: %v", err)
		}
		if n != int64(len(payload)) {
			b.Fatalf("bytes mismatch: got %d want %d", n, len(payload))
		}

		_ = dstRelay.CloseWrite()
		if err := <-writeErrCh; err != nil {
			b.Fatalf("writer failed: %v", err)
		}
		if err := <-drainErrCh; err != nil {
			b.Fatalf("drain failed: %v", err)
		}

		_ = srcWriter.Close()
		_ = srcRelay.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
	}
}

func benchmarkRelayPathWriteTo(b *testing.B, payload []byte, fn func(src Conn, dst io.Writer) (int64, error)) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))

	for i := 0; i < b.N; i++ {
		srcWriter, srcRelay := unixConnPair(b)
		dstRelay, dstReader := unixConnPair(b)

		writeErrCh := make(chan error, 1)
		go func() {
			_, err := srcWriter.Write(payload)
			if err == nil {
				err = srcWriter.CloseWrite()
			}
			writeErrCh <- err
		}()

		drainErrCh := make(chan error, 1)
		go func() {
			_, err := io.Copy(io.Discard, dstReader)
			drainErrCh <- err
		}()

		n, err := fn(srcRelay, dstRelay)
		if err != nil {
			b.Fatalf("relay failed: %v", err)
		}
		if n != int64(len(payload)) {
			b.Fatalf("bytes mismatch: got %d want %d", n, len(payload))
		}

		_ = dstRelay.CloseWrite()
		if err := <-writeErrCh; err != nil {
			b.Fatalf("writer failed: %v", err)
		}
		if err := <-drainErrCh; err != nil {
			b.Fatalf("drain failed: %v", err)
		}

		_ = srcWriter.Close()
		_ = srcRelay.Close()
		_ = dstRelay.Close()
		_ = dstReader.Close()
	}
}

func BenchmarkReadFromStrategyComparison(b *testing.B) {
	payload := bytes.Repeat([]byte{0xab}, 2<<20) // 2MB

	b.Run("legacy_direct_then_copy", func(b *testing.B) {
		benchmarkRelayPath(b, payload, legacyReadFrom)
	})
	b.Run("adaptive_direct_pipe_copy", func(b *testing.B) {
		benchmarkRelayPath(b, payload, ReadFrom)
	})
}

func BenchmarkWriteToStrategyComparison(b *testing.B) {
	payload := bytes.Repeat([]byte{0xcd}, 2<<20) // 2MB

	b.Run("legacy_direct_then_copy", func(b *testing.B) {
		benchmarkRelayPathWriteTo(b, payload, legacyWriteTo)
	})
	b.Run("adaptive_direct_pipe_copy", func(b *testing.B) {
		benchmarkRelayPathWriteTo(b, payload, WriteTo)
	})
}
