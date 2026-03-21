package xhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/daeuniverse/outbound/netproxy"
)

// Dialer implements Xray XHTTP / splithttp in packet-up mode (Xray default for TLS).
// stream-one, stream-up, stream-down, and xhttp+reality are not implemented.
type Dialer struct {
	nextDialer netproxy.Dialer
	dialAddr   string

	scheme   string
	urlHost  string
	urlPort  string
	pathRaw  string
	httpHost string
	mode     string

	forceH2 bool
}

// NewDialer parses s like httpupgrade: scheme http|https, Host = dial target, query host, path, mode, alpn.
func NewDialer(s string, d netproxy.Dialer) (*Dialer, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("xhttp: %w", err)
	}
	q := u.Query()
	path := q.Get("path")
	mode := strings.TrimSpace(strings.ToLower(q.Get("mode")))
	if mode == "" {
		mode = "auto"
	}
	httpHost := q.Get("host")
	if httpHost == "" {
		httpHost = u.Hostname()
	}
	urlPort := u.Port()
	if urlPort == "" {
		if u.Scheme == "https" {
			urlPort = "443"
		} else {
			urlPort = "80"
		}
	}
	alpn := strings.ToLower(q.Get("alpn"))
	forceH2 := strings.Contains(alpn, "h2") && !strings.Contains(alpn, "http/1.1")

	return &Dialer{
		nextDialer: d,
		dialAddr:   u.Host,
		scheme:     u.Scheme,
		urlHost:    httpHost,
		urlPort:    urlPort,
		pathRaw:    path,
		httpHost:   httpHost,
		mode:       mode,
		forceH2:    forceH2,
	}, nil
}

func (t *Dialer) packetUpMode() bool {
	switch t.mode {
	case "", "auto", "packet", "packet-up":
		return true
	default:
		return false
	}
}

func (t *Dialer) buildBaseURL() *url.URL {
	path, rawQuery := normalizedPathAndQuery(t.pathRaw)
	return &url.URL{
		Scheme:   t.scheme,
		Host:     net.JoinHostPort(t.urlHost, t.urlPort),
		Path:     path,
		RawQuery: rawQuery,
	}
}

func (t *Dialer) newHTTPClient() *http.Client {
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rc, err := t.nextDialer.DialContext(ctx, network, t.dialAddr)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: rc, LAddr: nil, RAddr: nil}, nil
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rc, err := t.nextDialer.DialContext(ctx, network, t.dialAddr)
			if err != nil {
				return nil, err
			}
			return &netproxy.FakeNetConn{Conn: rc, LAddr: nil, RAddr: nil}, nil
		},
		ForceAttemptHTTP2: t.forceH2,
		IdleConnTimeout:   0,
	}
	if !t.forceH2 {
		tr.DisableKeepAlives = true
	}
	return &http.Client{Transport: tr}
}

type xConn struct {
	downBody  io.ReadCloser
	client    *http.Client
	base      *url.URL
	sessionID string
	httpHost  string

	maxPost       int
	minIntervalMs int32

	uploadCtx context.Context
	cancel    context.CancelFunc

	mu        sync.Mutex
	seq       int64
	lastWrite time.Time
	closed    int32
}

func (c *xConn) Read(b []byte) (int, error) { return c.downBody.Read(b) }

func (c *xConn) Write(b []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, io.ErrClosedPipe
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for len(b) > 0 {
		chunkSize := len(b)
		if chunkSize > c.maxPost {
			chunkSize = c.maxPost
		}
		chunk := b[:chunkSize]
		b = b[chunkSize:]
		if c.minIntervalMs > 0 && !c.lastWrite.IsZero() {
			d := time.Duration(c.minIntervalMs)*time.Millisecond - time.Since(c.lastWrite)
			if d > 0 {
				time.Sleep(d)
			}
		}
		if err := c.postUnlocked(chunk); err != nil {
			return written, err
		}
		written += chunkSize
		c.lastWrite = time.Now()
	}
	return written, nil
}

func (c *xConn) postUnlocked(payload []byte) error {
	u := *c.base
	req, err := http.NewRequestWithContext(c.uploadCtx, http.MethodPost, u.String(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(payload))
	seqStr := strconv.FormatInt(c.seq, 10)
	c.seq++
	if err := fillPacketRequest(req, c.sessionID, seqStr); err != nil {
		return err
	}
	req.Host = c.httpHost

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp: upload status %s", resp.Status)
	}
	return nil
}

func (c *xConn) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	c.cancel()
	_ = c.downBody.Close()
	return nil
}

func (c *xConn) SetDeadline(_ time.Time) error      { return nil }
func (c *xConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *xConn) SetWriteDeadline(_ time.Time) error { return nil }

func (t *Dialer) DialContext(ctx context.Context, network, addr string) (netproxy.Conn, error) {
	magicNetwork, err := netproxy.ParseMagicNetwork(network)
	if err != nil {
		return nil, err
	}
	switch magicNetwork.Network {
	case "tcp":
	default:
		return nil, fmt.Errorf("%w: xhttp+%v", netproxy.UnsupportedTunnelTypeError, network)
	}

	if !t.packetUpMode() {
		return nil, fmt.Errorf("xhttp: mode %q is not supported (only packet-up / auto / packet)", t.mode)
	}

	base := t.buildBaseURL()
	sessionID := uuid.New().String()
	client := t.newHTTPClient()

	downURL := *base
	// GET 响应体会长期存活，不能用会在 Dial 返回后被上层 cancel 的 context（见 v2ray 测试）。
	// 建立阶段用 Background + select 同时尊重 ctx 取消与超时。
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	downReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, downURL.String(), nil)
	if err != nil {
		return nil, err
	}
	fillStreamRequest(downReq, sessionID)
	downReq.Host = t.httpHost

	type doRes struct {
		resp *http.Response
		err  error
	}
	ch := make(chan doRes, 1)
	go func() {
		r, e := client.Do(downReq)
		ch <- doRes{r, e}
	}()
	timer := time.NewTimer(45 * time.Second)
	defer timer.Stop()
	var resp *http.Response
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("xhttp: download: timeout")
	case res := <-ch:
		if res.err != nil {
			return nil, fmt.Errorf("xhttp: download: %w", res.err)
		}
		resp = res.resp
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("xhttp: download status %s", resp.Status)
	}

	maxPost := int(scMaxEachPostBytes().rand())
	if maxPost <= 0 {
		maxPost = 1000000
	}
	minInterval := scMinPostsIntervalMs().rand()

	uploadCtx, cancelUpload := context.WithCancel(context.Background())
	xc := &xConn{
		downBody:      resp.Body,
		client:        client,
		base:          base,
		sessionID:     sessionID,
		httpHost:      t.httpHost,
		maxPost:       maxPost,
		minIntervalMs: minInterval,
		uploadCtx:     uploadCtx,
		cancel:        cancelUpload,
	}
	return xc, nil
}
