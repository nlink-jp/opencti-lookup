package opencti

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/config"
)

func TestDownload(t *testing.T) {
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.EscapedPath(), r.Header.Get("Authorization")
		switch {
		case strings.Contains(path, "missing"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, `{"status":"error","error":"File not found or restricted"}`)
		case strings.Contains(path, "down"):
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "maintenance")
		case strings.Contains(path, "big"):
			_, _ = io.WriteString(w, strings.Repeat("x", 2048))
		case auth != "Bearer "+testToken:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "Forbidden")
		default:
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = io.WriteString(w, "%PDF-1.4 body")
		}
	}))
	defer srv.Close()
	c := New(&config.Config{URL: srv.URL, Token: testToken, Timeout: 5 * time.Second})

	var buf bytes.Buffer
	n, ctype, err := c.Download(context.Background(), "import/Report/r1/a b.pdf", &buf, 1024)
	if err != nil || n != int64(buf.Len()) || ctype != "application/pdf" || buf.String() != "%PDF-1.4 body" {
		t.Fatalf("%d %q %v %q", n, ctype, err, buf.String())
	}
	if path != "/storage/get/import%2FReport%2Fr1%2Fa%20b.pdf" || auth != "Bearer "+testToken {
		t.Fatalf("request %s %q", path, auth)
	}

	for id, code := range map[string]string{"missing.txt": CodeNotFound, "down.txt": CodeUpstreamError, "big.bin": CodeFileTooLarge} {
		_, _, err := c.Download(context.Background(), id, io.Discard, 1024)
		if Code(err) != code {
			t.Errorf("%s: %v", id, err)
		}
	}

	bad := New(&config.Config{URL: srv.URL, Token: "wrong", Timeout: 5 * time.Second})
	if _, _, err := bad.Download(context.Background(), "ok.pdf", io.Discard, 1024); Code(err) != CodeAuthFailed {
		t.Fatalf("bad token: %v", err)
	}
}
