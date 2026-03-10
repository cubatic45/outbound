package shadowsocks_2022

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
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

// Global option to control multi-PSK UDP optimization
// Set env var SS2022_UDP_MULTI_PSK_OPTIMIZATION=1 to enable aggressive optimization
// (send identity header only once, similar to TCP behavior)
var udpMultiPSKAggressiveOptimization = func() bool {
	if val := os.Getenv("SS2022_UDP_MULTI_PSK_OPTIMIZATION"); val != "" {
		if enabled, err := strconv.ParseBool(val); err == nil {
			return enabled
		}
	}
	return false // Default: conservative mode (send identity header every packet)
}()

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
		for i := 0; i < len(pskList)-1; i++ {
			hash := blake3.Sum512(pskList[i+1])
			// Store first aes.BlockSize (16) bytes of the hash
			component := make([]byte, aes.BlockSize)
			copy(component, hash[:aes.BlockSize])
			u.cachedIdentityComponents[i] = component
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
	if udpMultiPSKAggressiveOptimization && c.identityHeaderSent.Load() {
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

	// Aggressive optimization mode: send identity header only once
	// This matches TCP behavior and significantly reduces per-packet overhead
	// Use with caution: requires server-side compatibility
	if udpMultiPSKAggressiveOptimization {
		if c.identityHeaderSent.Load() {
			// Identity header already sent, skip for subsequent packets
			return 0, nil
		}

		// Send identity header for the first packet and cache it
		c.identityHeaderMutex.Lock()
		defer c.identityHeaderMutex.Unlock()

		// Double-check after acquiring lock
		if c.identityHeaderSent.Load() {
			return 0, nil
		}

		// Generate and cache the identity header.
		cachedHeader := make([]byte, len(c.cachedIdentityComponents)*aes.BlockSize)
		offset := 0
		for i := 0; i < len(c.cachedIdentityComponents); i++ {
			header := cachedHeader[offset : offset+aes.BlockSize]
			subtle.XORBytes(header, c.cachedIdentityComponents[i], separateHeader)
			b, err := c.cipherConf.NewBlockCipher(c.pskList[i])
			if err != nil {
				return 0, err
			}
			b.Encrypt(header, header)
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

	// Conservative mode: optimized multi-PSK with pre-computed hash components
	// Still sends identity header every packet, but avoids BLAKE3 recomputation
	headerLen := len(c.cachedIdentityComponents) * aes.BlockSize
	if len(dst) < headerLen {
		return 0, io.ErrShortBuffer
	}
	offset := 0
	for i := 0; i < len(c.cachedIdentityComponents); i++ {
		header := dst[offset : offset+aes.BlockSize]
		subtle.XORBytes(header, c.cachedIdentityComponents[i], separateHeader)
		b, err := c.cipherConf.NewBlockCipher(c.pskList[i])
		if err != nil {
			return 0, err
		}
		b.Encrypt(header, header)
		offset += aes.BlockSize
	}
	return headerLen, nil
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

	// Use bytes.Reader to simplify parsing
	reader := bytes.NewReader(payload)

	// Read header type
	var typ uint8
	if err := binary.Read(reader, binary.BigEndian, &typ); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read header type: %w", err)
	}

	// Read timestamp
	var timestampRaw uint64
	if err := binary.Read(reader, binary.BigEndian, &timestampRaw); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read timestamp: %w", err)
	}
	timestamp := time.Unix(int64(timestampRaw), 0)

	// Skip client session ID (8 bytes)
	if _, err := reader.Seek(8, io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip session ID: %w", err)
	}

	// Read padding length
	var paddingLength uint16
	if err := binary.Read(reader, binary.BigEndian, &paddingLength); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to read padding length: %w", err)
	}

	// Skip padding
	if _, err := reader.Seek(int64(paddingLength), io.SeekCurrent); err != nil {
		return 0, netip.AddrPort{}, fmt.Errorf("failed to skip padding: %w", err)
	}

	if typ != HeaderTypeServerStream {
		return 0, netip.AddrPort{}, fmt.Errorf("received unexpected header type: %d", typ)
	}

	if err := validateTimestamp(timestamp, now); err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Parse address from decrypted data
	netAddr, err := socks5.ReadAddr(reader)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	// Convert net.Addr to netip.AddrPort
	if udpAddr, ok := netAddr.(*net.UDPAddr); ok {
		ipAddr, _ := netip.AddrFromSlice(udpAddr.IP)
		addr = netip.AddrPortFrom(ipAddr, uint16(udpAddr.Port))
	}

	// Copy remaining data to output buffer
	n, err = reader.Read(b)
	return
}
