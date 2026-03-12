/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Package stickyip provides sticky IP caching for proxy server connections.
// Within a health check cycle, the same resolved IP is reused to ensure
// connection stability when a proxy domain resolves to multiple IPs.
package stickyip

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/sirupsen/logrus"
)

const (
	// CacheTTL is how long to cache a successful proxy IP.
	// This should be at least the health check interval to ensure
	// all connections in a cycle use the same IP.
	CacheTTL = 5 * time.Minute
)

// ProxyIpCache manages sticky IP resolution for proxy server domains.
// It separately caches IPs that work for TCP and UDP since some proxies
// may have different availability per protocol.
type ProxyIpCache struct {
	sync.RWMutex
	cache map[string]*proxyIpEntry
}

type proxyIpEntry struct {
	// tcpAddr is the IP:port that works for TCP connections.
	// May be empty if no TCP-validated IP is cached yet.
	tcpAddr string
	// udpAddr is the IP:port that works for UDP connections.
	// May be empty if no UDP-validated IP is cached yet.
	udpAddr string
	// expiresAt is when this cache entry expires.
	expiresAt time.Time
	// checkCycle is the health check cycle number this entry belongs to.
	checkCycle uint64
}

// NewProxyIpCache creates a new proxy IP cache.
func NewProxyIpCache() *ProxyIpCache {
	return &ProxyIpCache{
		cache: make(map[string]*proxyIpEntry),
	}
}

// Set stores a successful proxy IP address for a specific protocol with cycle tracking.
// network should be "tcp" or "udp" - this ensures we only cache IPs that actually work
// for the protocol being used.
func (c *ProxyIpCache) Set(originalAddr, actualAddr string, network string, cycle uint64) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	now := time.Now()

	// Get or create entry
	entry, exists := c.cache[originalAddr]
	if !exists {
		entry = &proxyIpEntry{
			expiresAt:  now.Add(CacheTTL),
			checkCycle: cycle,
		}
		c.cache[originalAddr] = entry
	}

	// Update the appropriate address based on network type
	isUDP := network == "udp"
	if isUDP {
		entry.udpAddr = actualAddr
		if logger.IsLevelEnabled(logrus.DebugLevel) {
			logger.WithFields(logrus.Fields{
				"original_addr": originalAddr,
				"udp_addr":      actualAddr,
				"cycle":         cycle,
			}).Debug("[StickyIP] Cached proxy IP for UDP")
		}
	} else {
		entry.tcpAddr = actualAddr
		if logger.IsLevelEnabled(logrus.DebugLevel) {
			logger.WithFields(logrus.Fields{
				"original_addr": originalAddr,
				"tcp_addr":      actualAddr,
				"cycle":         cycle,
			}).Debug("[StickyIP] Cached proxy IP for TCP")
		}
	}
}

// GetWithCycle returns the cached IP for the specified network if it belongs to the current check cycle.
// network should be "tcp" or "udp" - returns the protocol-specific cached IP.
func (c *ProxyIpCache) GetWithCycle(proxyAddr string, network string, currentCycle uint64) string {
	if c == nil {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] Cache is nil")
		return proxyAddr
	}
	c.RLock()
	defer c.RUnlock()
	entry, ok := c.cache[proxyAddr]
	if !ok {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] No cache entry found")
		return proxyAddr
	}
	if time.Now().After(entry.expiresAt) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"expired_at": entry.expiresAt,
		}).Debug("[StickyIP] Cache entry expired")
		return proxyAddr
	}
	// Only use cached IP if it's from the current cycle
	if entry.checkCycle != currentCycle {
		logger.WithFields(logrus.Fields{
			"proxy_addr":    proxyAddr,
			"entry_cycle":   entry.checkCycle,
			"current_cycle": currentCycle,
		}).Debug("[StickyIP] Cycle mismatch - cache not from current cycle")
		return proxyAddr
	}

	// Return the protocol-specific cached address
	isUDP := network == "udp"
	var cachedAddr string
	if isUDP {
		cachedAddr = entry.udpAddr
	} else {
		cachedAddr = entry.tcpAddr
	}

	if cachedAddr == "" {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"network":    network,
		}).Debug("[StickyIP] No cached IP for this network type")
		return proxyAddr
	}

	logger.WithFields(logrus.Fields{
		"proxy_addr":  proxyAddr,
		"cached_addr": cachedAddr,
		"network":     network,
	}).Debug("[StickyIP] Cache hit - returning cached IP")
	return cachedAddr
}

// Invalidate removes all cached entries for a proxy address.
func (c *ProxyIpCache) Invalidate(proxyAddr string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	delete(c.cache, proxyAddr)
}

// InvalidateProtocol removes the cached entry for a specific protocol (tcp/udp).
// This allows TCP and UDP to use different IPs when one protocol fails.
func (c *ProxyIpCache) InvalidateProtocol(proxyAddr, network string) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	entry, exists := c.cache[proxyAddr]
	if !exists {
		return
	}

	isUDP := network == "udp"
	if isUDP {
		entry.udpAddr = ""
		// If both are empty now, remove the entry entirely
		if entry.tcpAddr == "" {
			delete(c.cache, proxyAddr)
		} else {
			logger.WithFields(logrus.Fields{
				"proxy_addr": proxyAddr,
				"network":    network,
			}).Debug("[StickyIP] Invalidated UDP cache, TCP cache retained")
		}
	} else {
		entry.tcpAddr = ""
		if entry.udpAddr == "" {
			delete(c.cache, proxyAddr)
		} else {
			logger.WithFields(logrus.Fields{
				"proxy_addr": proxyAddr,
				"network":    network,
			}).Debug("[StickyIP] Invalidated TCP cache, UDP cache retained")
		}
	}
}

// InvalidateCycle removes all cache entries for a specific cycle.
func (c *ProxyIpCache) InvalidateCycle(cycle uint64) {
	if c == nil {
		return
	}
	c.Lock()
	defer c.Unlock()
	for addr, entry := range c.cache {
		if entry.checkCycle == cycle {
			delete(c.cache, addr)
		}
	}
}

// StickyIpDialer wraps a dialer to provide sticky IP caching for proxy servers.
type StickyIpDialer struct {
	dialer     netproxy.Dialer
	cache      *ProxyIpCache
	checkCycle uint64
	proxyAddr  string // Original proxy address (domain:port or IP:port)
	proxyHost  string
}

// NewStickyIpDialer creates a new sticky IP dialer wrapper.
func NewStickyIpDialer(dialer netproxy.Dialer, proxyAddr string, cache *ProxyIpCache) *StickyIpDialer {
	if cache == nil {
		cache = NewProxyIpCache()
	}
	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithField("proxy_addr", proxyAddr).Debug("[StickyIP] NewStickyIpDialer created")
	}
	return &StickyIpDialer{
		dialer:     dialer,
		cache:      cache,
		checkCycle: 0,
		proxyAddr:  proxyAddr,
		proxyHost:  proxyHost,
	}
}

// IncrementCheckCycle advances the health check cycle.
func (d *StickyIpDialer) IncrementCheckCycle() {
	oldCycle := d.checkCycle
	d.checkCycle++
	logger.WithFields(logrus.Fields{
		"old_cycle":  oldCycle,
		"new_cycle":  d.checkCycle,
		"proxy_addr": d.proxyAddr,
	}).Debug("[StickyIP] Check cycle incremented")
	// Invalidate old cycle entries to force refresh
	d.cache.InvalidateCycle(d.checkCycle - 1)
}

// InvalidateProtocolCache invalidates the cached IP for a specific protocol.
// This is called when a connection fails (e.g., connection refused) to allow
// immediate retry with a different IP.
func (d *StickyIpDialer) InvalidateProtocolCache(proxyAddr, protocol string) {
	d.cache.InvalidateProtocol(proxyAddr, protocol)
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"protocol":   protocol,
		}).Debug("[StickyIP] Protocol cache invalidated due to connection failure")
	}
}

// GetCachedProxyAddr returns the cached IP for the proxy address and network type.
// network should be "tcp" or "udp".
func (d *StickyIpDialer) GetCachedProxyAddr(network string) string {
	if d == nil {
		return ""
	}
	return d.cache.GetWithCycle(d.proxyAddr, network, d.checkCycle)
}

// DialContext implements sticky IP caching by intercepting dial calls.
// It resolves all IPs for the target, tries the cached IP first, then falls back.
// For UDP, it verifies UDP connectivity before caching an IP.
func (d *StickyIpDialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	// Extract the base network type (tcp/udp) from magic network if present
	baseNetwork := d.getBaseNetwork(network)

	// Log every dial attempt for debugging
	logger.WithFields(logrus.Fields{
		"proxy_addr":   d.proxyAddr,
		"target":       addr,
		"network":      network,
		"base_network": baseNetwork,
		"is_proxy":     d.isProxyAddress(addr),
	}).Debug("[StickyIP] DialContext called")

	// Check if we should use a cached proxy IP for this connection
	if d.isProxyAddress(addr) {
		cachedAddr := d.GetCachedProxyAddr(baseNetwork)
		// Only use cached IP if it's different from proxy address (i.e., it's a resolved IP)
		// GetCachedProxyAddr returns proxyAddr when cache is empty/expired, so we need to check
		if cachedAddr != "" && cachedAddr != d.proxyAddr {
			// Try with cached IP first
			conn, err := d.dialer.DialContext(ctx, network, cachedAddr)
			if err == nil {
				// For UDP, verify the connection actually works by trying to read
				if baseNetwork == "udp" {
					if !d.verifyUDPConnectivity(ctx, conn.(netproxy.PacketConn)) {
						conn.Close()
						logCacheFailure(d.proxyAddr, cachedAddr, network, fmt.Errorf("UDP verification failed"))
						d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
						// Fall through to resolve and try other IPs
					} else {
						// UDP verification succeeded
						logCacheHit(d.proxyAddr, cachedAddr, network)
						return conn, nil
					}
				} else {
					// TCP - connection success is enough
					logCacheHit(d.proxyAddr, cachedAddr, network)
					return conn, nil
				}
			} else {
				// Log cache miss/failure
				logCacheFailure(d.proxyAddr, cachedAddr, network, err)
				// Cached IP failed, invalidate this protocol's cache
				d.cache.InvalidateProtocol(d.proxyAddr, baseNetwork)
			}
		}
		// No cached IP, or cached IP failed - resolve and try all IPs
		logger.WithFields(logrus.Fields{
			"proxy_addr":  d.proxyAddr,
			"target":      addr,
			"network":     network,
			"cached_addr": cachedAddr,
		}).Debug("[StickyIP] No valid cached IP - resolving proxy domain")
		return d.dialWithIpResolution(ctx, network, addr, baseNetwork)
	}

	// Not the proxy address, just pass through
	logger.WithFields(logrus.Fields{
		"proxy_addr": d.proxyAddr,
		"target":     addr,
		"network":    network,
	}).Trace("[StickyIP] Pass-through (not proxy address)")
	return d.dialer.DialContext(ctx, network, addr)
}

// getBaseNetwork extracts the base network type (tcp/udp) from magic network.
func (d *StickyIpDialer) getBaseNetwork(network string) string {
	// Parse magic network to get base type
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		// Default to treating as-is
		return network
	}
	return magicNetwork.Network
}

// verifyUDPConnectivity checks if a UDP connection is actually working.
// For UDP, we do a basic sanity check by trying to read with a short deadline.
// Note: UDP connectivity can only be truly verified by sending/receiving actual data,
// so this is a best-effort check. The real validation happens during protocol handshake.
func (d *StickyIpDialer) verifyUDPConnectivity(ctx context.Context, conn netproxy.PacketConn) bool {
	// Set a very short read deadline
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	// Try to read - this will tell us if the socket is properly bound
	var buf [1]byte
	_, _, err := conn.ReadFrom(buf[:])

	if err != nil {
		// A timeout is expected and means the socket is working (just no data yet)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return true
		}
		// Check for immediate connection refused
		if opErr, ok := err.(*net.OpError); ok {
			if opErr.Err.Error() == "connection refused" {
				logger.WithField("error", err).Debug("[StickyIP] UDP connection refused detected")
				return false
			}
		}
		// Other errors at this stage are inconclusive for UDP
		// The socket might be fine, just no data available
		logger.WithField("error", err).Trace("[StickyIP] UDP verification read error (inconclusive)")
	}

	// If we got here without a definitive failure, consider the socket potentially working
	return true
}

// isProxyAddress checks if the given address matches the proxy address.
func (d *StickyIpDialer) isProxyAddress(addr string) bool {
	// Exact match
	if addr == d.proxyAddr {
		return true
	}
	// Check if host part matches
	addrHost, _, err := net.SplitHostPort(addr)
	if err == nil && d.proxyHost != "" {
		return d.proxyHost == addrHost
	}
	return false
}

// dialWithIpResolution resolves the address to IPs and tries each one.
// The first successful IP is cached for subsequent connections.
func (d *StickyIpDialer) dialWithIpResolution(ctx context.Context, network, addr, baseNetwork string) (netproxy.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// Not in host:port format, try directly
		logResolutionError(d.proxyAddr, "invalid address format", err)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// If already an IP address, dial directly
	if ip := net.ParseIP(host); ip != nil {
		logDirectDial(d.proxyAddr, addr, network)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// Resolve to get all IPs
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		// Resolution failed, try original address
		logResolutionError(d.proxyAddr, host, err)
		return d.dialer.DialContext(ctx, network, addr)
	}

	// Log all resolved IPs
	logResolvedIPs(d.proxyAddr, ips, port, network)

	// Extract base network type for protocol-specific caching
	isUDP := baseNetwork == "udp"

	// Try each IP until one works
	var lastErr error
	for _, ipAddr := range ips {
		if ipAddr.IP == nil {
			continue
		}
		ipAddrStr := ipAddr.IP.String()
		targetAddr := net.JoinHostPort(ipAddrStr, port)

		logTryingIP(d.proxyAddr, targetAddr, network)
		conn, err := d.dialer.DialContext(ctx, network, targetAddr)
		if err == nil {
			// For UDP, verify the connection actually works
			if isUDP {
				packetConn, ok := conn.(netproxy.PacketConn)
				if !ok {
					conn.Close()
					lastErr = fmt.Errorf("not a packet connection")
					logIPFailure(d.proxyAddr, targetAddr, lastErr)
					continue
				}
				if !d.verifyUDPConnectivity(ctx, packetConn) {
					conn.Close()
					lastErr = fmt.Errorf("UDP connection verification failed")
					logIPFailure(d.proxyAddr, targetAddr, lastErr)
					continue
				}
			}

			// This IP works for this protocol, cache it
			d.cache.Set(d.proxyAddr, targetAddr, baseNetwork, d.checkCycle)
			logIPSuccess(d.proxyAddr, targetAddr, baseNetwork, d.checkCycle)
			return conn, nil
		}
		lastErr = err
		logIPFailure(d.proxyAddr, targetAddr, err)
	}

	// All IPs failed, return an error
	logAllIPsFailed(d.proxyAddr, lastErr)
	return nil, &net.OpError{Op: "dial", Err: lastErr}
}

// Logging functions for debugging sticky IP caching

var logger = logrus.StandardLogger()

func logCacheHit(proxyAddr, cachedAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
		}).Debug("[StickyIP] Cache hit - using cached proxy IP")
	}
}

func logCacheFailure(proxyAddr, cachedAddr, network string, err error) {
	if logger.IsLevelEnabled(logrus.WarnLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"cached_ip":  cachedAddr,
			"network":    network,
			"error":      err.Error(),
		}).Warn("[StickyIP] Cached IP failed - invalidating and re-resolving")
	}
}

func logResolutionError(proxyAddr, host string, err error) {
	if logger.IsLevelEnabled(logrus.WarnLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"host":       host,
			"error":      err.Error(),
		}).Warn("[StickyIP] DNS resolution failed")
	}
}

func logDirectDial(proxyAddr, addr, network string) {
	if logger.IsLevelEnabled(logrus.TraceLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     addr,
			"network":    network,
		}).Trace("[StickyIP] Direct dial (already an IP)")
	}
}

func logResolvedIPs(proxyAddr string, ips []net.IPAddr, port, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		ipList := make([]string, 0, len(ips))
		for _, ip := range ips {
			if ip.IP != nil {
				ipList = append(ipList, ip.IP.String())
			}
		}
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"ips":        ipList,
			"port":       port,
			"network":    network,
			"count":      len(ipList),
		}).Debug("[StickyIP] Resolved proxy domain to IPs")
	}
}

func logTryingIP(proxyAddr, targetAddr, network string) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"network":    network,
		}).Debug("[StickyIP] Trying proxy IP")
	}
}

func logIPSuccess(proxyAddr, targetAddr, network string, cycle uint64) {
	if logger.IsLevelEnabled(logrus.DebugLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr":  proxyAddr,
			"selected_ip": targetAddr,
			"network":     network,
			"cycle":       cycle,
		}).Debug("[StickyIP] Successfully connected to proxy IP")
	}
}

func logIPFailure(proxyAddr, targetAddr string, err error) {
	if logger.IsLevelEnabled(logrus.WarnLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"target":     targetAddr,
			"error":      err.Error(),
		}).Warn("[StickyIP] Failed to connect to proxy IP")
	}
}

func logAllIPsFailed(proxyAddr string, lastErr error) {
	if logger.IsLevelEnabled(logrus.ErrorLevel) {
		logger.WithFields(logrus.Fields{
			"proxy_addr": proxyAddr,
			"error":      lastErr.Error(),
		}).Error("[StickyIP] All proxy IPs failed - connection refused")
	}
}
