package opencti

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/config"
)

const testToken = "11111111-2222-4333-8444-555555555555"

// serve answers every request with status and body, and records the last request.
func serve(t *testing.T, status int, body string) (*httptest.Server, *http.Request) {
	t.Helper()
	var last http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = *r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &last
}

func client(srv *httptest.Server) *Client {
	return New(&config.Config{URL: srv.URL + "/sub", Token: testToken, Timeout: 5 * time.Second})
}

func TestQuerySuccess(t *testing.T) {
	srv, last := serve(t, 200, `{"data":{"about":{"version":"6.7.4"}}}`)
	var out struct {
		About struct{ Version string } `json:"about"`
	}
	if err := client(srv).Query(context.Background(), "{ about { version } }", nil, &out); err != nil {
		t.Fatal(err)
	}
	if out.About.Version != "6.7.4" {
		t.Fatalf("version %q", out.About.Version)
	}
	if last.Method != http.MethodPost || last.URL.Path != "/sub/graphql" {
		t.Fatalf("request %s %s", last.Method, last.URL.Path)
	}
	if got := last.Header.Get("Authorization"); got != "Bearer "+testToken {
		t.Fatalf("Authorization %q", got)
	}
	if strings.Contains(last.URL.RawQuery, testToken) {
		t.Fatal("the token must travel in the header only")
	}
}

func TestQuerySendsVariables(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"data":{}}`)
	}))
	defer srv.Close()
	if err := client(srv).Query(context.Background(), "q", map[string]any{"first": 3}, nil); err != nil {
		t.Fatal(err)
	}
	if got["query"] != "q" || got["variables"].(map[string]any)["first"] != float64(3) {
		t.Fatalf("body %v", got)
	}
}

// The error bodies are the shapes Phase 0 captured from OpenCTI 6.7.4
// (dev/captures/err-*.json), trimmed to what classification reads.
func TestClassification(t *testing.T) {
	cases := []struct {
		name, body string
		status     int
		code       string
		mention    string
	}{
		{"auth", `{"errors":[{"message":"You must be logged in to do this.","extensions":{"code":"AUTH_REQUIRED","data":{"http_status":401}}}],"data":{"about":null}}`, 200, CodeAuthFailed, "check token"},
		{"forbidden", `{"errors":[{"message":"You are not allowed to do this.","extensions":{"code":"FORBIDDEN_ACCESS"}}],"data":{"capabilities":null}}`, 200, CodeForbidden, "not allowed"},
		{"partial success is a failure", `{"errors":[{"message":"You are not allowed to do this.","extensions":{"code":"FORBIDDEN_ACCESS"}}],"data":{"reports":{"edges":[]},"capabilities":null}}`, 200, CodeForbidden, ""},
		{"parse", `{"errors":[{"message":"Syntax Error: Expected Name, found <EOF>.","extensions":{"code":"GRAPHQL_PARSE_FAILED"}}]}`, 200, CodeQueryRejected, "server_status"},
		{"validation", `{"errors":[{"message":"Cannot query field","extensions":{"code":"GRAPHQL_VALIDATION_FAILED"}}]}`, 200, CodeQueryRejected, "GRAPHQL_VALIDATION_FAILED"},
		{"unsupported filter", `{"errors":[{"message":"incorrect filter keys","extensions":{"code":"UNSUPPORTED_ERROR"}}],"data":{"x":null}}`, 200, CodeQueryRejected, ""},
		{"database", `{"errors":[{"message":"Fail to execute engine pagination","extensions":{"code":"DATABASE_ERROR","cause":{"body":"SECRET-ES-QUERY group-id-123"}}}],"data":{"x":null}}`, 200, CodeUpstreamError, "DATABASE_ERROR"},
		{"introspection 500", `{"errors":[{"message":"Internal server error","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}`, 500, CodeUpstreamError, ""},
		{"no code", `{"errors":[{"message":"boom"}]}`, 200, CodeUpstreamError, "no code"},
		{"html from a proxy", `<html><body>Bad Gateway</body></html>`, 502, CodeUpstreamError, "HTTP 502"},
		{"empty data", `{"data":null}`, 200, CodeUpstreamError, "neither"},
		{"non-200 with data", `{"data":{}}`, 503, CodeUpstreamError, "HTTP 503"},
		{"auth wins over forbidden", `{"errors":[{"message":"a","extensions":{"code":"FORBIDDEN_ACCESS"}},{"message":"b","extensions":{"code":"AUTH_REQUIRED"}}]}`, 200, CodeAuthFailed, "1 more"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, _ := serve(t, c.status, c.body)
			var out map[string]any
			err := client(srv).Query(context.Background(), "q", nil, &out)
			if Code(err) != c.code {
				t.Fatalf("Code = %q (%v); want %q", Code(err), err, c.code)
			}
			if c.mention != "" && !strings.Contains(err.Error(), c.mention) {
				t.Fatalf("message %q lacks %q", err.Error(), c.mention)
			}
			if strings.Contains(err.Error(), "SECRET-ES-QUERY") || strings.Contains(err.Error(), "group-id-123") {
				t.Fatalf("extensions.cause leaked: %q", err.Error())
			}
			if strings.Contains(err.Error(), testToken) {
				t.Fatal("the token leaked into an error")
			}
		})
	}
}

func TestShapeMismatchIsQueryRejected(t *testing.T) {
	srv, _ := serve(t, 200, `{"data":{"about":"not an object"}}`)
	var out struct {
		About struct{ Version string } `json:"about"`
	}
	if err := client(srv).Query(context.Background(), "q", nil, &out); Code(err) != CodeQueryRejected {
		t.Fatalf("Code = %q (%v)", Code(err), err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	followed := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = true
	}))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/graphql", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	err := client(srv).Query(context.Background(), "q", nil, nil)
	if followed || Code(err) != CodeUnreachable || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("followed=%v err=%v", followed, err)
	}
}

func TestUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c := New(&config.Config{URL: url, Token: testToken, Timeout: 2 * time.Second})
	if err := c.Query(context.Background(), "q", nil, nil); Code(err) != CodeUnreachable {
		t.Fatalf("Code = %q (%v)", Code(err), err)
	}
}

func TestTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	c := New(&config.Config{URL: srv.URL, Token: testToken, Timeout: 100 * time.Millisecond})
	err := c.Query(context.Background(), "q", nil, nil)
	if Code(err) != CodeUnreachable || !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("err = %v", err)
	}
}

func TestTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"about":{"version":"6.7.4"}}}`)
	}))
	defer srv.Close()

	verified := New(&config.Config{URL: srv.URL, Token: testToken, Timeout: 5 * time.Second})
	err := verified.Query(context.Background(), "q", nil, nil)
	if Code(err) != CodeUnreachable || !strings.Contains(err.Error(), "ca_file") || !strings.Contains(err.Error(), "insecure_skip_verify") {
		t.Fatalf("untrusted certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	withCA := New(&config.Config{URL: srv.URL, Token: testToken, Timeout: 5 * time.Second, CAPool: pool})
	if err := withCA.Query(context.Background(), "q", nil, nil); err != nil {
		t.Fatalf("with ca_file: %v", err)
	}

	insecure := New(&config.Config{URL: srv.URL, Token: testToken, Timeout: 5 * time.Second, InsecureSkipVerify: true})
	if err := insecure.Query(context.Background(), "q", nil, nil); err != nil {
		t.Fatalf("insecure: %v", err)
	}
}
