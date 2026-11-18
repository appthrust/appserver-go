package requestlog

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
)

type responseWriter struct {
	http.ResponseWriter
	state    *requestState
	status   int // zero until a final status is committed
	bytes    int64
	hijacked bool
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// RecordRequestError is the private writer protocol shared with httpx.
func (w *responseWriter) RecordRequestError(code string, detail error) {
	w.state.setError(code, detail)
}

func (w *responseWriter) WriteHeader(status int) {
	if w.hijacked {
		return
	}
	w.ResponseWriter.WriteHeader(status)
	// Informational headers other than 101 may precede the final status.
	if w.status == 0 && (status >= 200 || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
}

func (w *responseWriter) wrote(n int) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.bytes += int64(n)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.hijacked {
		return 0, http.ErrHijacked
	}
	n, err := w.ResponseWriter.Write(b)
	w.wrote(n)
	return n, err
}

func (w *responseWriter) WriteString(s string) (int, error) {
	if w.hijacked {
		return 0, http.ErrHijacked
	}
	n, err := io.WriteString(w.ResponseWriter, s)
	w.wrote(n)
	return n, err
}

func (w *responseWriter) Flush() { _ = w.FlushError() }

func (w *responseWriter) FlushError() error {
	if w.hijacked {
		return http.ErrHijacked
	}
	err := http.NewResponseController(w.ResponseWriter).Flush()
	if !errors.Is(err, http.ErrNotSupported) {
		w.wrote(0)
	}
	return err
}

// Only advertise Hijacker when supported (notably, not on HTTP/2). Account
// for hijacks even when another middleware wrapped the underlying writer.
func (w *responseWriter) withHijacker() http.ResponseWriter {
	for inner := w.ResponseWriter; inner != nil; {
		if h, ok := inner.(http.Hijacker); ok {
			return &hijackWriter{w, h}
		}
		u, ok := inner.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		inner = u.Unwrap()
	}
	return w
}

type hijackWriter struct {
	*responseWriter
	hijacker http.Hijacker
}

func (w *hijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.hijacked {
		return nil, nil, http.ErrHijacked
	}
	conn, buf, err := w.hijacker.Hijack()
	if err == nil {
		w.hijacked = true
		if w.status == 0 {
			w.status = http.StatusSwitchingProtocols
		}
	}
	return conn, buf, err
}
