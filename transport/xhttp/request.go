package xhttp

import (
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"net/url"
	"strings"
)

// Defaults aligned with Xray-core transport/internet/splithttp/config.go (packet-up).
const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"

type rangeCfg struct {
	from, to int32
}

func (r rangeCfg) rand() int32 {
	if r.to <= r.from {
		return r.from
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	u := binary.BigEndian.Uint64(b[:])
	span := uint64(r.to-r.from) + 1
	return r.from + int32(u%span)
}

func normalizedPathAndQuery(pathField string) (path string, rawQuery string) {
	parts := strings.SplitN(pathField, "?", 2)
	path = parts[0]
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}
	if len(parts) > 1 {
		rawQuery = parts[1]
	}
	return path, rawQuery
}

func appendToPath(path, value string) string {
	if strings.HasSuffix(path, "/") {
		return path + value
	}
	return path + "/" + value
}

func applyMetaToPath(u *url.URL, sessionID, seqStr string) {
	if sessionID != "" {
		u.Path = appendToPath(u.Path, sessionID)
	}
	if seqStr != "" {
		u.Path = appendToPath(u.Path, seqStr)
	}
}

// default padding: Referer = request URL with query replaced by x_padding= (Xray splithttp default).
func applyDefaultXPadding(req *http.Request, rawURL string, padLen int) {
	if padLen <= 0 {
		return
	}
	padding := strings.Repeat("X", padLen)
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return
	}
	u.RawQuery = "x_padding=" + padding
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Referer", u.String())
}

func xPaddingBytesRange() rangeCfg {
	return rangeCfg{from: 100, to: 1000}
}

func scMaxEachPostBytes() rangeCfg {
	return rangeCfg{from: 1000000, to: 1000000}
}

func scMinPostsIntervalMs() rangeCfg {
	return rangeCfg{from: 30, to: 30}
}

func fillStreamRequest(req *http.Request, sessionID string) {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("User-Agent", chromeUA)
	padLen := int(xPaddingBytesRange().rand())
	applyDefaultXPadding(req, req.URL.String(), padLen)
	applyMetaToPath(req.URL, sessionID, "")
}

func fillPacketRequest(req *http.Request, sessionID, seqStr string) error {
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("User-Agent", chromeUA)
	padLen := int(xPaddingBytesRange().rand())
	applyDefaultXPadding(req, req.URL.String(), padLen)
	applyMetaToPath(req.URL, sessionID, seqStr)
	return nil
}
