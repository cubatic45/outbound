package anytls

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

type session struct {
	conn netproxy.Conn

	streams    map[uint32]*stream
	streamLock sync.RWMutex

	sid atomic.Uint32
}

func newSession(conn netproxy.Conn) (*session, error) {
	return &session{
		conn:    conn,
		streams: map[uint32]*stream{},
	}, nil
}

func (s *session) newStream(addr string) (netproxy.Conn, error) {
	frame := newFrame(cmdSettings, s.sid.Load())
	frame.data = settingsBytes
	if _, err := writeFrame(s.conn, frame); err != nil {
		return nil, err
	}
	s.sid.Add(1)

	frame = newFrame(cmdSYN, s.sid.Load())
	if _, err := writeFrame(s.conn, frame); err != nil {
		return nil, err
	}

	tgtAddr, err := socks.ParseAddr(addr)
	if err != nil {
		return nil, err
	}
	frame = newFrame(cmdPSH, s.sid.Load())
	frame.data = tgtAddr
	if _, err := writeFrame(s.conn, frame); err != nil {
		return nil, err
	}

	adr, _ := netip.ParseAddrPort(addr)
	stream := newStream(s.conn, adr, s.sid.Load())
	s.streamLock.Lock()
	s.streams[s.sid.Load()] = stream
	s.streamLock.Unlock()

	return stream, nil
}

func (s *session) run() error {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("[Panic]", slog.String("stack", string(debug.Stack())))
		}
	}()
	defer s.Close()

	var header rawHeader
	for {
		if s.Closed() {
			return net.ErrClosed
		}
		if _, err := io.ReadFull(s.conn, header[:]); err != nil {
			return err
		}
		sid := header.StreamID()
		length := int(header.Length())
		switch header.Cmd() {
		case cmdWaste:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			pool.Put(buf)
		case cmdPSH:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				if _, err := stream.pw.Write(buf); err != nil {
					pool.Put(buf)
					return err
				}
			}
			pool.Put(buf)
		case cmdAlert:
			buf := pool.Get(length)
			if _, err := io.ReadFull(s.conn, buf); err != nil {
				pool.Put(buf)
				return err
			}
			slog.Error("[Alert]", slog.String("msg", string(buf)))
			pool.Put(buf)
		case cmdFIN:
			s.streamLock.RLock()
			stream, ok := s.streams[sid]
			s.streamLock.RUnlock()
			if ok {
				stream.Close()
				s.streamLock.Lock()
				delete(s.streams, sid)
				s.streamLock.Unlock()
			}
		default:
			return fmt.Errorf("invalid cmd: %d", header.Cmd())
		}
	}
}

func (s *session) Close()       {}
func (s *session) Closed() bool { return false }
