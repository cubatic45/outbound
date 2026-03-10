package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol/socks5"
	"lukechampine.com/blake3"
)

func BenchmarkParseDecryptedPayload_Baseline(b *testing.B) {
	payload := benchmarkPayloadIPv4(1200)
	output := make([]byte, 1400)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := parseDecryptedPayloadBaseline(payload, output, now)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDecryptedPayload_Optimized(b *testing.B) {
	payload := benchmarkPayloadIPv4(1200)
	output := make([]byte, 1400)
	now := time.Now()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := parseDecryptedPayload(payload, output, now)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUDPAddrParse_IPv4(b *testing.B) {
	payload := []byte{byte(socks5.AddressTypeIPv4), 1, 2, 3, 4, 0, 53}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := parseUDPAddrPort(payload, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteIdentityHeader_Baseline(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	pskList := benchmarkPSKList()
	separateHeader := make([]byte, aes.BlockSize)
	fastrand.Read(separateHeader)
	dst := make([]byte, (len(pskList)-1)*aes.BlockSize)
	components := benchmarkIdentityComponents(pskList)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := writeIdentityHeaderBaseline(dst, separateHeader, components, pskList, conf); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkWriteIdentityHeader_CachedBlocks(b *testing.B) {
	conf := ciphers.Aead2022CiphersConf["2022-blake3-aes-256-gcm"]
	pskList := benchmarkPSKList()
	u, err := NewUdpConn(nil, conf, nil, nil, pskList, pskList[len(pskList)-1], nil)
	if err != nil {
		b.Fatal(err)
	}
	separateHeader := make([]byte, aes.BlockSize)
	fastrand.Read(separateHeader)
	dst := make([]byte, (len(pskList)-1)*aes.BlockSize)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := u.writeIdentityHeader(dst, separateHeader); err != nil {
			b.Fatal(err)
		}
	}
}

func TestParseDecryptedPayload_IPv4(t *testing.T) {
	payload := benchmarkPayloadIPv4(32)
	buf := make([]byte, 64)

	n, addr, err := parseDecryptedPayload(payload, buf, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("1.2.3.4:53"); addr != want {
		t.Fatalf("unexpected addr: got %v want %v", addr, want)
	}
	if n != 32 {
		t.Fatalf("unexpected payload length: got %d want 32", n)
	}
}

func TestParseDecryptedPayload_DomainParsed(t *testing.T) {
	payload := benchmarkPayloadDomain("example.com", 443, 8)
	buf := make([]byte, 32)

	n, addr, err := parseDecryptedPayload(payload, buf, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Domain addresses return empty AddrPort but are successfully parsed
	if addr.IsValid() {
		t.Fatalf("expected empty addr for domain, got %v", addr)
	}
	if n != 8 {
		t.Fatalf("unexpected payload length: got %d want 8", n)
	}
}

func TestParseUDPAddrPort_IPv6(t *testing.T) {
	payload := append([]byte{byte(socks5.AddressTypeIPv6)}, append(netip.MustParseAddr("2001:db8::1").AsSlice(), 0, 80)...)

	addr, next, err := parseUDPAddrPort(payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("[2001:db8::1]:80"); addr != want {
		t.Fatalf("unexpected addr: got %v want %v", addr, want)
	}
	if next != len(payload) {
		t.Fatalf("unexpected offset: got %d want %d", next, len(payload))
	}
}

func parseDecryptedPayloadBaseline(payload []byte, dst []byte, now time.Time) (n int, addr netip.AddrPort, err error) {
	reader := bytes.NewReader(payload)

	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, err
	}

	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, err
	}
	timestamp := time.Unix(int64(timestampRaw), 0)
	if _, err := reader.Seek(8, 1); err != nil {
		return 0, netip.AddrPort{}, err
	}

	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if _, err := reader.Seek(int64(paddingLength), 1); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, err
	}
	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if udpAddr, ok := netAddr.(*net.UDPAddr); ok {
		ipAddr, _ := netip.AddrFromSlice(udpAddr.IP)
		addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))
	}
	n, err = reader.Read(dst)
	return n, addr, err
}

func benchmarkPayloadIPv4(payloadLen int) []byte {
	body := make([]byte, payloadLen)
	fastrand.Read(body)

	packet := make([]byte, 19+1+4+2+len(body))
	packet[0] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(packet[1:9], uint64(time.Now().Unix()))
	packet[19] = byte(socks5.AddressTypeIPv4)
	copy(packet[20:24], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(packet[24:26], 53)
	copy(packet[26:], body)
	return packet
}

func benchmarkPayloadDomain(host string, port uint16, payloadLen int) []byte {
	body := make([]byte, payloadLen)
	fastrand.Read(body)

	packet := make([]byte, 19+1+1+len(host)+2+len(body))
	packet[0] = HeaderTypeServerStream
	binary.BigEndian.PutUint64(packet[1:9], uint64(time.Now().Unix()))
	packet[19] = byte(socks5.AddressTypeDomain)
	packet[20] = byte(len(host))
	copy(packet[21:21+len(host)], host)
	binary.BigEndian.PutUint16(packet[21+len(host):23+len(host)], port)
	copy(packet[23+len(host):], body)
	return packet
}

func benchmarkPSKList() [][]byte {
	pskList := make([][]byte, 3)
	for i := range pskList {
		pskList[i] = make([]byte, 32)
		fastrand.Read(pskList[i])
	}
	return pskList
}

func benchmarkIdentityComponents(pskList [][]byte) [][]byte {
	components := make([][]byte, len(pskList)-1)
	for i := 0; i < len(pskList)-1; i++ {
		hash := blake3.Sum512(pskList[i+1])
		component := make([]byte, aes.BlockSize)
		copy(component, hash[:aes.BlockSize])
		components[i] = component
	}
	return components
}

func writeIdentityHeaderBaseline(dst []byte, separateHeader []byte, components [][]byte, pskList [][]byte, conf *ciphers.CipherConf2022) error {
	offset := 0
	for i := 0; i < len(components); i++ {
		header := dst[offset : offset+aes.BlockSize]
		subtle.XORBytes(header, components[i], separateHeader)
		block, err := conf.NewBlockCipher(pskList[i])
		if err != nil {
			return err
		}
		block.Encrypt(header, header)
		offset += aes.BlockSize
	}
	return nil
}
