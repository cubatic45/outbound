package anytls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

func init() {
	protocol.Register("anytls", NewDialer)
}

type Dialer struct {
	proxyAddress string
	nextDialer   netproxy.Dialer
	metadata     protocol.Metadata
	key          []byte
	tlsConfig    *tls.Config
}

func NewDialer(nextDialer netproxy.Dialer, header protocol.Header) (netproxy.Dialer, error) {
	metadata := protocol.Metadata{
		IsClient: header.IsClient,
	}
	sum := sha256.Sum256([]byte(header.Password))
	return &Dialer{
		proxyAddress: header.ProxyAddress,
		nextDialer:   nextDialer,
		metadata:     metadata,
		key:          sum[:],
		tlsConfig:    header.TlsConfig,
	}, nil
}

func (d *Dialer) DialTcp(ctx context.Context, addr string) (c netproxy.Conn, err error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *Dialer) DialUdp(ctx context.Context, addr string) (c netproxy.PacketConn, err error) {
	pktConn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	return pktConn.(netproxy.PacketConn), nil
}

func (d *Dialer) DialContext(ctx context.Context, network string, addr string) (c netproxy.Conn, err error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp", "udp":
		mdata, err := protocol.ParseMetadata(addr)
		if err != nil {
			return nil, err
		}
		mdata.IsClient = d.metadata.IsClient
		if magicNetwork.Network == "udp" {
			mdata.Hostname = "sp.v2.udp-over-tcp.arpa"
		}
		tcpNetwork := netproxy.MagicNetwork{
			Network: "tcp",
			Mark:    magicNetwork.Mark,
			Mptcp:   magicNetwork.Mptcp,
		}.Encode()
		s, err := d.loadSession(func() (netproxy.Conn, error) {
			conn, err := d.nextDialer.DialContext(ctx, tcpNetwork, d.proxyAddress)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(conn.(net.Conn), d.tlsConfig)

			password := d.key
			b := make([]byte, len(password)+2)
			copy(b, password)
			binary.BigEndian.PutUint16(b[len(password):], uint16(0))
			if _, err := tlsConn.Write(b); err != nil {
				return nil, err
			}
			return tlsConn, nil
		})
		addr := fmt.Sprintf("%s:%d", mdata.Hostname, mdata.Port)
		if err != nil {
			return nil, err
		}
		go s.run()
		return s.newStream(addr)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, magicNetwork.Network)
	}
}

func (d *Dialer) loadSession(f func() (netproxy.Conn, error)) (*session, error) {
	conn, err := f()
	if err != nil {
		return nil, err
	}
	return newSession(conn)
}
