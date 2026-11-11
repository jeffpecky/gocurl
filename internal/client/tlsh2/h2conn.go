// Package tlsh2 implements a minimal, fingerprint-exact HTTP/2 client for
// one-shot requests.  Standard Go transports (net/http, x/net/http2) hardcode
// the client preface: the SETTINGS frame contents and order, the connection
// WINDOW_UPDATE, and the header field order — all of which are part of the
// Akamai HTTP/2 fingerprint.  This package sends the preface and the request
// headers exactly as the active profile specifies, then reads the response
// frames.
//
// It is deliberately not a general-purpose HTTP/2 client: one request per
// connection, no stream multiplexing, no push, no trailers.  That is all a
// curl-style CLI needs, and it is what keeps the framer small enough to
// control byte-for-byte.
package tlsh2

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	hpack "golang.org/x/net/http2/hpack"
)

// Frame types (RFC 7540 section 6).
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
)

// Setting IDs (RFC 7540 section 6.5.2).
const (
	SettingHeaderTableSize      = 0x1
	SettingEnablePush           = 0x2
	SettingMaxConcurrentStreams = 0x3
	SettingInitialWindowSize    = 0x4
	SettingMaxFrameSize         = 0x5
	SettingMaxHeaderListSize    = 0x6
	SettingEnableConnectProto   = 0x8
)

// Flags for HEADERS frames.
const (
	flagEndStream  = 0x1
	flagEndHeaders = 0x4
)

const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// Setting is a single SETTINGS entry in wire order.
type Setting struct {
	ID  uint16
	Val uint32
}

// Fingerprint describes the HTTP/2 connection fingerprint the profile wants
// on the wire.
type Fingerprint struct {
	// Settings is the ordered SETTINGS frame contents.  Sending nothing means
	// an empty SETTINGS frame (which is what real browsers never do — profiles
	// must always fill this in).
	Settings []Setting

	// ConnWindowUpdate is the connection-level WINDOW_UPDATE increment sent
	// right after SETTINGS.  0 means the frame is not sent.
	ConnWindowUpdate uint32

	// PseudoHeaderOrder is the wire order of the request pseudo-headers,
	// given as single letters: m(:method), s(:scheme), a(:authority),
	// p(:path).
	PseudoHeaderOrder string
}

// Request is the single request sent over the connection.
type Request struct {
	Method    string
	Scheme    string
	Authority string
	Path      string

	// HeaderFields are the request headers in exact wire order (after the
	// pseudo-headers).  The caller must not include pseudo-headers here.
	HeaderFields []HeaderField

	// Body may be nil.
	Body []byte
}

// HeaderField is a single request header in wire order.
type HeaderField struct {
	Name  string
	Value string
}

// Response is the parsed response of the single request.
type Response struct {
	StatusCode int
	// HeaderFields are the response headers in wire order.
	HeaderFields []HeaderField
	// Body is the concatenated DATA payload until END_STREAM.
	Body []byte
}

// Do sends req over conn using fp as the connection fingerprint and returns
// the response.  conn is closed before returning.
func Do(ctx context.Context, conn net.Conn, fp *Fingerprint, req *Request) (resp *Response, err error) {
	defer func() {
		if r := recover(); r != nil {
			resp, err = nil, fmt.Errorf("h2 protocol error: %v", r)
		}
		_ = conn.Close()
	}()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	w := newFrameWriter(conn)

	// Client connection preface.
	if _, err := io.WriteString(w.w, clientPreface); err != nil {
		return nil, err
	}

	// SETTINGS frame, in the profile's order.
	settingsPayload := make([]byte, 0, len(fp.Settings)*6)
	for _, s := range fp.Settings {
		var entry [6]byte
		binary.BigEndian.PutUint16(entry[0:2], s.ID)
		binary.BigEndian.PutUint32(entry[2:6], s.Val)
		settingsPayload = append(settingsPayload, entry[:]...)
	}
	if err := w.writeFrame(frameSettings, 0, 0, settingsPayload); err != nil {
		return nil, err
	}

	// Connection-level WINDOW_UPDATE (if the profile sends one).
	if fp.ConnWindowUpdate > 0 {
		var inc [4]byte
		binary.BigEndian.PutUint32(inc[:], fp.ConnWindowUpdate)
		if err := w.writeFrame(frameWindowUpdate, 0, 0, inc[:]); err != nil {
			return nil, err
		}
	}

	// Stream-level initial window as adjusted by the profile's
	// SETTINGS_INITIAL_WINDOW_SIZE (65535 by spec default).
	streamWindow := initialStreamWindow(fp)

	// HEADERS frame with the exact header order.
	hb, err := encodeHeaders(fp, req)
	if err != nil {
		return nil, err
	}

	flags := byte(flagEndHeaders)
	if req.Body == nil {
		flags |= flagEndStream
	}
	if err := w.writeFrame(frameHeaders, flags, 1, hb); err != nil {
		return nil, err
	}

	// DATA frame(s) if there is a body.
	if req.Body != nil {
		if err := w.writeDataFrame(1, req.Body, streamWindow); err != nil {
			return nil, err
		}
	}

	return readResponse(conn, streamWindow)
}

// initialStreamWindow returns the stream-level initial window as adjusted by
// the fingerprint's SETTINGS_INITIAL_WINDOW_SIZE (65535 by spec default).
func initialStreamWindow(fp *Fingerprint) uint32 {
	for _, s := range fp.Settings {
		if s.ID == SettingInitialWindowSize {
			return s.Val
		}
	}

	return 65535
}

// encodeHeaders HPACK-encodes the pseudo-headers in the profile's order and
// then the regular headers in the given order.
func encodeHeaders(fp *Fingerprint, req *Request) ([]byte, error) {
	var buf strings.Builder
	enc := hpack.NewEncoder(&bufWriter{&buf})
	enc.SetMaxDynamicTableSizeLimit(65536)

	pseudo := map[rune][2]string{
		'm': {":method", req.Method},
		's': {":scheme", req.Scheme},
		'a': {":authority", req.Authority},
		'p': {":path", req.Path},
	}
	for _, r := range fp.PseudoHeaderOrder {
		f, ok := pseudo[r]
		if !ok {
			return nil, fmt.Errorf("bad pseudo-header order %q", fp.PseudoHeaderOrder)
		}
		if err := enc.WriteField(hpack.HeaderField{Name: f[0], Value: f[1]}); err != nil {
			return nil, err
		}
	}

	for _, f := range req.HeaderFields {
		if strings.HasPrefix(f.Name, ":") {
			return nil, fmt.Errorf("pseudo-header %q must come from the profile order", f.Name)
		}
		if err := enc.WriteField(hpack.HeaderField{Name: f.Name, Value: f.Value}); err != nil {
			return nil, err
		}
	}

	return []byte(buf.String()), nil
}

// readResponse reads the response frames of the single request until
// END_STREAM on stream 1.
func readResponse(conn net.Conn, streamWindow uint32) (*Response, error) {
	r := &frameReader{r: bufio.NewReader(conn)}
	resp := &Response{}
	bodyFlow := streamWindow

	for {
		fh, payload, err := r.readFrame()
		if err != nil {
			return nil, err
		}

		switch fh.Type {
		case frameSettings, frameWindowUpdate, framePing:
			// Server-timed frames; ignore for one-shot requests.

		case frameGoAway:
			return nil, fmt.Errorf("server sent GOAWAY: %q", payload)

		case frameHeaders:
			// Response headers (or trailers).  Decode with a fresh decoder:
			// the dynamic table state of the response stream is independent
			// of the encoder's.
			dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
				resp.HeaderFields = append(resp.HeaderFields, HeaderField{Name: f.Name, Value: f.Value})
			})
			block := payload
			// Skip priority fields if the PRIORITY flag is set.
			if fh.Flags&0x20 != 0 && len(block) >= 5 {
				block = block[5:]
			}
			if _, err := dec.Write(block); err != nil {
				return nil, fmt.Errorf("decoding response headers: %w", err)
			}
			for _, f := range resp.HeaderFields {
				if f.Name == ":status" {
					resp.StatusCode, _ = strconv.Atoi(f.Value)
				}
			}
			if fh.Flags&flagEndStream != 0 {
				return resp, nil
			}

		case frameData:
			bodyFlow -= uint32(len(payload))
			resp.Body = append(resp.Body, payload...)
			if fh.Flags&flagEndStream != 0 {
				return resp, nil
			}
			// Grow the receive window as we consume data so the server can
			// keep streaming.  One WINDOW_UPDATE per DATA frame is fine for
			// a curl-style response body.
			if bodyFlow < streamWindow/2 {
				var inc [4]byte
				binary.BigEndian.PutUint32(inc[:], streamWindow-bodyFlow)
				w2 := newFrameWriter(conn)
				if err := w2.writeFrame(frameWindowUpdate, 0, 1, inc[:]); err != nil {
					return nil, err
				}
				bodyFlow = streamWindow
			}

		case frameRSTStream:
			return nil, fmt.Errorf("stream reset by server")

		default:
			// Unknown/unsupported frame types must be skipped per spec.
		}
	}
}

// bufWriter adapts a strings.Builder to io.Writer for the hpack encoder.
type bufWriter struct {
	b *strings.Builder
}

func (w *bufWriter) Write(p []byte) (int, error) {
	return w.b.Write(p)
}

// frameWriter writes frames to a buffered writer.
type frameWriter struct {
	w *bufio.Writer
}

func newFrameWriter(conn net.Conn) *frameWriter {
	return &frameWriter{w: bufio.NewWriter(conn)}
}

func (fw *frameWriter) writeFrame(typ, flags byte, streamID uint32, payload []byte) error {
	var hdr [9]byte
	hdr[0] = byte(len(payload) >> 16)
	hdr[1] = byte(len(payload) >> 8)
	hdr[2] = byte(len(payload))
	hdr[3] = typ
	hdr[4] = flags
	binary.BigEndian.PutUint32(hdr[5:9], streamID)

	if _, err := fw.w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := fw.w.Write(payload); err != nil {
		return err
	}

	return fw.w.Flush()
}

// writeDataFrame sends the request body, respecting the stream window.
func (fw *frameWriter) writeDataFrame(streamID uint32, body []byte, window uint32) error {
	if uint32(len(body)) > window {
		return fmt.Errorf("request body %d bytes exceeds initial stream window %d", len(body), window)
	}

	return fw.writeFrame(frameData, flagEndStream, streamID, body)
}

// frameReader reads frames off the connection.
type frameReader struct {
	r *bufio.Reader
}

func (fr *frameReader) readFrame() (fh frameHeader, payload []byte, err error) {
	var hdr [9]byte
	if _, err = io.ReadFull(fr.r, hdr[:]); err != nil {
		return fh, nil, err
	}
	length := int(hdr[0])<<16 | int(hdr[1])<<8 | int(hdr[2])
	fh = frameHeader{
		Length:   length,
		Type:     hdr[3],
		Flags:    hdr[4],
		StreamID: binary.BigEndian.Uint32(hdr[5:9]) & 0x7fffffff,
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(fr.r, payload); err != nil {
		return fh, nil, err
	}

	return fh, payload, nil
}

// frameHeader is a parsed frame header.
type frameHeader struct {
	Length   int
	Type     byte
	Flags    byte
	StreamID uint32
}
