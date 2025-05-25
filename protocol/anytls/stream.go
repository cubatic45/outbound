package anytls

import (
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol/infra/socks"
)

var (
	_ netproxy.Conn       = (*stream)(nil)
	_ netproxy.PacketConn = (*stream)(nil)
)

type stream struct {
	netproxy.Conn

	pr *io.PipeReader
	pw *io.PipeWriter

	writeMutex sync.Mutex
	readMutex  sync.Mutex

	addr netip.AddrPort

	udpWriteAddr atomic.Bool

	id uint32
}

func newStream(conn netproxy.Conn, addr netip.AddrPort, id uint32) *stream {
	pr, pw := io.Pipe()
	return &stream{
		Conn: conn,
		pr:   pr,
		pw:   pw,
		addr: addr,
		id:   id,
	}
}

func (c *stream) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	frame := newFrame(cmdPSH, c.id)
	frame.data = b
	return writeFrame(c.Conn, frame)
}

func (c *stream) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	return c.pr.Read(b)
}

func (c *stream) ReadFrom(p []byte) (int, netip.AddrPort, error) {
	var length uint16
	if err := binary.Read(c, binary.BigEndian, &length); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if len(p) < int(length) {
		return 0, netip.AddrPort{}, io.ErrShortBuffer
	}
	n, err := io.ReadFull(c, p[:length])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, c.addr, nil
}

func (c *stream) WriteTo(p []byte, addr string) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()

	if c.udpWriteAddr.CompareAndSwap(false, true) {
		tgtAddr, err := socks.ParseAddr(addr)
		if err != nil {
			return 0, err
		}
		data := pool.Get(1 + len(tgtAddr) + 2 + len(p))
		defer pool.Put(data)
		// connected mode
		data[0] = 1
		copy(data[1:], tgtAddr)
		binary.BigEndian.PutUint16(data[1+len(tgtAddr):], uint16(len(p)))
		copy(data[1+len(tgtAddr)+2:], p)

		frame := newFrame(cmdPSH, c.id)
		frame.data = data
		if _, err := writeFrame(c.Conn, frame); err != nil {
			return 0, err
		}
		c.addr, _ = netip.ParseAddrPort(addr)
		return len(p), nil
	}

	data := pool.Get(2 + len(p))
	defer pool.Put(data)
	binary.BigEndian.PutUint16(data, uint16(len(p)))
	copy(data[2:], p)

	frame := newFrame(cmdPSH, c.id)
	frame.data = data
	if _, err := writeFrame(c.Conn, frame); err != nil {
		return 0, err
	}
	c.addr, _ = netip.ParseAddrPort(addr)
	return len(p), nil
}
