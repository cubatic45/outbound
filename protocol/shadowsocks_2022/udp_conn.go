package shadowsocks_2022

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/ciphers"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/pool"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/socks5"
	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/samber/oops"
	"lukechampine.com/blake3"
)


type UdpConn struct {
	net.Conn

	sessionID [8]byte
	packetID  atomic.Uint64

	cipherConf         *ciphers.CipherConf2022
	blockCipherEncrypt cipher.Block
	blockCipherDecrypt cipher.Block

	pskList [][]byte
	uPSK    []byte
	bloom   *disk_bloom.FilterGroup

	replayWindow sync.Map

	cachedIdentityComponents [][]byte
	cachedIdentityBlocks     []cipher.Block
	identityHeaderCache      atomic.Value
	identityHeaderMutex      sync.Mutex
	hasMultiPSK              bool
	identityHeaderSent       atomic.Bool

	cleanupCounter atomic.Int64
}

const (
	udpPacketReplayWindowSize = 1024
	maxTrackedUdpSessions     = 128
)

type udpSessionReplayState struct {
	filter   *ciphers.SlidingWindowFilter
	lastSeen atomic.Int64 // Unix nano timestamp
}

func NewUdpConn(conn net.Conn, conf *ciphers.CipherConf2022, blockCipherEncrypt cipher.Block, blockCipherDecrypt cipher.Block, pskList [][]byte, uPSK []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	u := UdpConn{
		Conn:               conn,
		cipherConf:         conf,
		blockCipherEncrypt: blockCipherEncrypt,
		blockCipherDecrypt: blockCipherDecrypt,
		pskList:            pskList,
		uPSK:               uPSK,
		bloom:              bloom,
		hasMultiPSK:        len(pskList) > 1,
	}
	fastrand.Read(u.sessionID[:])

	// Pre-compute identity header components for multi-PSK scenario
	// This cache stores BLAKE3 hashes of each PSK for fast identity header generation
	if u.hasMultiPSK {
		u.cachedIdentityComponents = make([][]byte, len(pskList)-1)
		u.cachedIdentityBlocks = make([]cipher.Block, len(pskList)-1)
		for i := 0; i < len(pskList)-1; i++ {
			hash := blake3.Sum512(pskList[i+1])
			// Store first aes.BlockSize (16) bytes of the hash
			component := make([]byte, aes.BlockSize)
			copy(component, hash[:aes.BlockSize])
			u.cachedIdentityComponents[i] = component
			block, err := conf.NewBlockCipher(pskList[i])
			if err != nil {
				return nil, err
			}
			u.cachedIdentityBlocks[i] = block
		}
	}

	return &u, nil
}

func (c *UdpConn) nextPacketID() uint64 {
	return c.packetID.Add(1)
}

func (c *UdpConn) checkAndUpdateReplay(sessionID [8]byte, packetID uint64, now time.Time) bool {
	nowNano := now.UnixNano()
	expireNano := ciphers.SaltStorageDuration.Nanoseconds()

	if v, ok := c.replayWindow.Load(sessionID); ok {
		state := v.(*udpSessionReplayState)
		lastSeen := state.lastSeen.Load()
		if nowNano-lastSeen > expireNano {
			c.replayWindow.CompareAndDelete(sessionID, v)
		} else {
			state.lastSeen.Store(nowNano)
			return state.filter.CheckAndUpdate(packetID)
		}
	}

	if c.cleanupCounter.Add(1)%cleanupInterval == 0 {
		go c.cleanupExpiredSessions(nowNano, expireNano)
	}

	newState := &udpSessionReplayState{
		filter: ciphers.NewSlidingWindowFilter(udpPacketReplayWindowSize),
	}
	newState.lastSeen.Store(nowNano)

	actual, loaded := c.replayWindow.LoadOrStore(sessionID, newState)
	state := actual.(*udpSessionReplayState)

	if loaded {
		state.lastSeen.Store(nowNano)
	} else {
		c.evictOldestIfNeeded()
	}

	return state.filter.CheckAndUpdate(packetID)
}

const cleanupInterval = 1000

func (c *UdpConn) cleanupExpiredSessions(nowNano, expireNano int64) {
	c.replayWindow.Range(func(key, value interface{}) bool {
		state := value.(*udpSessionReplayState)
		if nowNano-state.lastSeen.Load() > expireNano {
			c.replayWindow.Delete(key)
		}
		return true
	})
}

// evictOldestIfNeeded evicts the oldest session if we exceed max sessions
func (c *UdpConn) evictOldestIfNeeded() {
	var count int
	var oldestKey [8]byte
	var oldestNano int64 = ^int64(0) // max int64

	c.replayWindow.Range(func(key, value interface{}) bool {
		count++
		state := value.(*udpSessionReplayState)
		seen := state.lastSeen.Load()
		if seen < oldestNano {
			oldestKey = key.([8]byte)
			oldestNano = seen
		}
		return true
	})

	if count > maxTrackedUdpSessions {
		c.replayWindow.Delete(oldestKey)
	}
}

func (c *UdpConn) estimateIdentityHeaderLen() int {
	if !c.hasMultiPSK {
		return 0
	}
	// Aggressive optimization: send identity header only once per UdpConn
	if c.identityHeaderSent.Load() {
		return 0
	}
	if cached, ok := c.identityHeaderCache.Load().([]byte); ok {
		return len(cached)
	}
	return len(c.cachedIdentityComponents) * aes.BlockSize
}

func (c *UdpConn) writeIdentityHeader(dst []byte, separateHeader []byte) (int, error) {
	// Fast path: single PSK - no identity header needed
	if !c.hasMultiPSK {
		return 0, nil
	}

	// Aggressive optimization: send identity header only once per UdpConn
	// This matches TCP behavior and significantly reduces per-packet overhead
	if c.identityHeaderSent.Load() {
		return 0, nil
	}

	// Send identity header for the first packet and cache it
	c.identityHeaderMutex.Lock()
	defer c.identityHeaderMutex.Unlock()

	// Double-check after acquiring lock
	if c.identityHeaderSent.Load() {
		return 0, nil
	}

	// Generate and cache the identity header
	cachedHeader := make([]byte, len(c.cachedIdentityComponents)*aes.BlockSize)
	offset := 0
	for i := 0; i < len(c.cachedIdentityComponents); i++ {
		header := cachedHeader[offset : offset+aes.BlockSize]
		subtle.XORBytes(header, c.cachedIdentityComponents[i], separateHeader)
		c.cachedIdentityBlocks[i].Encrypt(header, header)
		offset += aes.BlockSize
	}

	c.identityHeaderCache.Store(cachedHeader)
	c.identityHeaderSent.Store(true)
	if len(dst) < len(cachedHeader) {
		return 0, io.ErrShortBuffer
	}
	copy(dst, cachedHeader)
	return len(cachedHeader), nil
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	packetID := c.nextPacketID()
	var separateHeader [16]byte
	copy(separateHeader[:8], c.sessionID[:])
	binary.BigEndian.PutUint64(separateHeader[8:], packetID)

	var separateHeaderEncrypted [16]byte
	c.blockCipherEncrypt.Encrypt(separateHeaderEncrypted[:], separateHeader[:])

	addrInfo, err := socks5.AddressFromString(addr)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to parse target address")
	}
	addrLen, err := addrInfoEncodedLen(addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to calculate address length")
	}
	messageLen := 1 + 8 + 2 + addrLen + len(b)
	totalPacketLen := len(separateHeaderEncrypted) + c.estimateIdentityHeaderLen() + messageLen + c.cipherConf.TagLen
	packet := pool.Get(totalPacketLen)
	defer pool.Put(packet)
	offset := 0
	copy(packet[offset:], separateHeaderEncrypted[:])
	offset += len(separateHeaderEncrypted)

	identityHeaderLen, err := c.writeIdentityHeader(packet[offset:], separateHeader[:])
	if err != nil {
		return 0, oops.Wrapf(err, "fail to write identity header")
	}
	offset += identityHeaderLen

	messageOffset := offset
	message := packet[messageOffset : messageOffset+messageLen]
	message[0] = HeaderTypeClientStream
	binary.BigEndian.PutUint64(message[1:9], uint64(time.Now().Unix()))
	// No padding.
	binary.BigEndian.PutUint16(message[9:11], 0)
	addrWritten, err := writeAddrInfoTo(message[11:], addrInfo)
	if err != nil {
		return 0, oops.Wrapf(err, "fail to encode target address")
	}
	copy(message[11+addrWritten:], b)

	// Encrypt and send
	// Optimized: Use cached cipher for session reuse
	cipher, err := GetCachedCipher(c.uPSK, separateHeader[:8], c.cipherConf, true)
	if err != nil {
		return 0, err
	}
	packet = cipher.Seal(packet[:messageOffset], separateHeader[4:16], message, nil)

	_, err = c.Conn.Write(packet)
	return len(b), err
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	buf := pool.Get(len(b) + 16 + c.cipherConf.TagLen)
	defer pool.Put(buf)
	n, err = c.Conn.Read(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 16 {
		return 0, netip.AddrPort{}, fmt.Errorf("short length to decrypt")
	}

	c.blockCipherDecrypt.Decrypt(buf[:16], buf[:16])
	var sessionID [8]byte
	copy(sessionID[:], buf[:8])
	packetID := binary.BigEndian.Uint64(buf[8:16])
	now := time.Now()
	if !c.checkAndUpdateReplay(sessionID, packetID, now) {
		return 0, netip.AddrPort{}, protocol.ErrReplayAttack
	}

	payload := buf[16:n]
	// Optimized: Use cached cipher for session reuse
	ciph, err := GetCachedCipher(c.uPSK, buf[:8], c.cipherConf, false)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload, err = ciph.Open(payload[:0], buf[4:16], payload, nil)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	return parseDecryptedPayload(payload, b, now)
}

func parseDecryptedPayload(payload []byte, dst []byte, now time.Time) (n int, addr netip.AddrPort, err error) {
	if len(payload) < 19 {
		return 0, netip.AddrPort{}, fmt.Errorf("payload too short: %d", len(payload))
	}

	headerType := payload[0]
	if headerType != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", headerType)
	}

	timestamp := time.Unix(int64(binary.BigEndian.Uint64(payload[1:9])), 0)
	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	paddingLength := int(binary.BigEndian.Uint16(payload[17:19]))
	offset := 19 + paddingLength
	if offset >= len(payload) {
		return 0, netip.AddrPort{}, fmt.Errorf("payload too short for address")
	}

	addr, offset, err = parseUDPAddrPort(payload, offset)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	return copy(dst, payload[offset:]), addr, nil
}

func parseUDPAddrPort(payload []byte, offset int) (netip.AddrPort, int, error) {
	if offset >= len(payload) {
		return netip.AddrPort{}, offset, fmt.Errorf("payload truncated at address type")
	}

	addrType := payload[offset]
	offset++

	switch addrType {
	case byte(socks5.AddressTypeIPv4):
		if offset+6 > len(payload) {
			return netip.AddrPort{}, offset, fmt.Errorf("payload truncated at IPv4 address")
		}
		ip, ok := netip.AddrFromSlice(payload[offset : offset+4])
		if !ok {
			return netip.AddrPort{}, offset, fmt.Errorf("invalid IPv4 address")
		}
		port := binary.BigEndian.Uint16(payload[offset+4 : offset+6])
		return netip.AddrPortFrom(ip, port), offset + 6, nil
	case byte(socks5.AddressTypeIPv6):
		if offset+18 > len(payload) {
			return netip.AddrPort{}, offset, fmt.Errorf("payload truncated at IPv6 address")
		}
		ip, ok := netip.AddrFromSlice(payload[offset : offset+16])
		if !ok {
			return netip.AddrPort{}, offset, fmt.Errorf("invalid IPv6 address")
		}
		port := binary.BigEndian.Uint16(payload[offset+16 : offset+18])
		return netip.AddrPortFrom(ip, port), offset + 18, nil
	case byte(socks5.AddressTypeDomain):
		if offset >= len(payload) {
			return netip.AddrPort{}, offset, fmt.Errorf("payload truncated at domain length")
		}
		domainLen := int(payload[offset])
		offset++
		if offset+domainLen+2 > len(payload) {
			return netip.AddrPort{}, offset, fmt.Errorf("payload truncated at domain address")
		}
		// For domain addresses, we return an empty AddrPort.
		// The caller should handle domain addresses separately if needed.
		// This maintains API compatibility while allowing domain parsing.
		_ = string(payload[offset : offset+domainLen]) // domain name (currently unused)
		// port := binary.BigEndian.Uint16(payload[offset+domainLen : offset+domainLen+2])
		// Note: Domain addresses are parsed but not returned via netip.AddrPort.
		// For sniffing purposes, the raw payload should be inspected.
		return netip.AddrPort{}, offset + domainLen + 2, nil
	default:
		return netip.AddrPort{}, offset, fmt.Errorf("invalid address: invalid type: %v", addrType)
	}
}
