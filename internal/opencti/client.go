// Package opencti is the GraphQL client for an OpenCTI instance: one POST to
// <url>/graphql per query, the token in the Authorization header only, and
// every failure classified into a stable code.
//
// Classification follows what OpenCTI 6.7.4 was measured to do (Phase 0
// record §2): most errors arrive with HTTP 200 and their kind in
// errors[].extensions.code; whole-schema introspection answers HTTP 500; a
// query that includes a field the key may not read returns data for the other
// fields and an error for that one. Any entry in errors fails the call — a
// partial answer is never handed on as a complete one — and the error's
// extensions.cause, which carries Elasticsearch query bodies and internal ids,
// is never passed on.
package opencti

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/nlink-jp/opencti-lookup/internal/config"
)

// Error codes. Every Code* constant under internal/ is documented in usage.md.
const (
	// CodeAuthFailed: the token is missing, wrong or expired (AUTH_REQUIRED).
	CodeAuthFailed = "auth_failed"
	// CodeForbidden: the key may not do this (FORBIDDEN_ACCESS).
	CodeForbidden = "forbidden"
	// CodeQueryRejected: the instance did not accept this tool's query —
	// usually a different OpenCTI version than the one verified.
	CodeQueryRejected = "query_rejected"
	// CodeUpstreamError: the instance failed while answering.
	CodeUpstreamError = "upstream_error"
	// CodeUnreachable: no answer at all — network, DNS, TLS or timeout.
	CodeUnreachable = "unreachable"
)

// maxBody bounds what one reply may hold. 5,000 relationship rows with their
// ends measured about 4 MB; this leaves room without letting a broken proxy
// stream forever.
const maxBody = 64 << 20

// Error is a classified failure.
type Error struct {
	Code         string // one of the Code* constants
	Message      string
	UpstreamCode string // extensions.code as OpenCTI sent it, when there was one
	HTTPStatus   int
}

func (e *Error) Error() string { return e.Message }

// Code returns the classification of err, or "" when err is not an *Error.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Client talks to one OpenCTI instance.
type Client struct {
	base  string
	host  string // for explaining a certificate that names another host
	token string
	http  *http.Client
}

// New builds a client from resolved settings: the timeout, the CA pool or the
// operator's decision to skip verification, and no redirects (a redirect could
// carry the request — and the token — somewhere the operator did not name).
func New(cfg *config.Config) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.CAPool,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // the operator's documented, warned choice
	}
	hc := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return NewWithHTTP(cfg.URL, cfg.Token, hc)
}

// NewWithHTTP builds a client over a given http.Client (tests).
func NewWithHTTP(base, token string, hc *http.Client) *Client {
	c := &Client{base: strings.TrimRight(base, "/"), token: token, http: hc}
	if u, err := url.Parse(c.base); err == nil {
		c.host = u.Hostname()
	}
	return c
}

type gqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

type gqlError struct {
	Message    string `json:"message"`
	Extensions struct {
		Code string `json:"code"`
	} `json:"extensions"`
}

type gqlReply struct {
	Data   json.RawMessage `json:"data"`
	Errors []gqlError      `json:"errors"`
}

// Query runs one GraphQL document and decodes its data into out.
func (c *Client) Query(ctx context.Context, query string, vars map[string]any, out any) error {
	body, err := json.Marshal(gqlRequest{Query: query, Variables: vars})
	if err != nil {
		return fmt.Errorf("encode query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/graphql", bytes.NewReader(body))
	if err != nil {
		return &Error{Code: CodeUnreachable, Message: "build request: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return transportError(err, c.host)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return &Error{Code: CodeUnreachable, Message: "read reply: " + err.Error(), HTTPStatus: resp.StatusCode}
	}
	if len(raw) > maxBody {
		return &Error{Code: CodeUpstreamError, Message: fmt.Sprintf("reply over %d MB; ask for fewer rows", maxBody>>20), HTTPStatus: resp.StatusCode}
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return &Error{Code: CodeUnreachable, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(
			"the instance answered with a redirect (HTTP %d to %q), which this tool does not follow: set url to where it points", resp.StatusCode, resp.Header.Get("Location"))}
	}

	var reply gqlReply
	if jerr := json.Unmarshal(raw, &reply); jerr != nil {
		return &Error{Code: CodeUpstreamError, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(
			"the instance did not answer with GraphQL JSON (HTTP %d%s): is url the OpenCTI base URL?", resp.StatusCode, snippet(raw))}
	}
	if len(reply.Errors) > 0 {
		return classify(reply.Errors, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return &Error{Code: CodeUpstreamError, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("HTTP %d from the instance", resp.StatusCode)}
	}
	if len(reply.Data) == 0 || string(reply.Data) == "null" {
		return &Error{Code: CodeUpstreamError, HTTPStatus: resp.StatusCode, Message: "the reply held neither data nor errors"}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(reply.Data, out); err != nil {
		return &Error{Code: CodeQueryRejected, HTTPStatus: resp.StatusCode, Message: "the reply does not have the shape this tool expects (" + err.Error() + "); check the version with server_status"}
	}
	return nil
}

// classify turns OpenCTI's errors into one Error. When several are present the
// one that most changes what the caller should do wins: a dead token over a
// missing permission over everything else.
func classify(errs []gqlError, status int) *Error {
	rank := func(code string) int {
		switch code {
		case "AUTH_REQUIRED":
			return 0
		case "FORBIDDEN_ACCESS":
			return 1
		}
		return 2
	}
	best := errs[0]
	for _, e := range errs[1:] {
		if rank(e.Extensions.Code) < rank(best.Extensions.Code) {
			best = e
		}
	}
	up := best.Extensions.Code
	msg := best.Message
	if len(errs) > 1 {
		msg = fmt.Sprintf("%s (and %d more error(s))", msg, len(errs)-1)
	}
	e := &Error{UpstreamCode: up, HTTPStatus: status}
	switch up {
	case "AUTH_REQUIRED":
		e.Code = CodeAuthFailed
		e.Message = "the instance refused the token (" + msg + "): check token"
	case "FORBIDDEN_ACCESS":
		e.Code = CodeForbidden
		e.Message = "this key is not allowed to do this (" + msg + ")"
	case "GRAPHQL_PARSE_FAILED", "GRAPHQL_VALIDATION_FAILED", "BAD_USER_INPUT", "UNSUPPORTED_ERROR", "FUNCTIONAL_ERROR":
		e.Code = CodeQueryRejected
		e.Message = "the instance rejected this tool's query (" + up + ": " + msg + "); if server_status reports a version other than the verified one, that is the likely cause"
	default:
		e.Code = CodeUpstreamError
		if up == "" {
			up = "no code"
		}
		e.Message = "the instance failed while answering (" + up + ": " + msg + ")"
	}
	return e
}

// transportError classifies a failure to get any HTTP answer. A certificate
// problem gets directions, because a self-hosted instance with an untrusted
// certificate is the expected case, not an exotic one.
func transportError(err error, host string) *Error {
	if e, ok := certificateError(err, host); ok {
		return e
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), isTimeout(err):
		return &Error{Code: CodeUnreachable, Message: "no answer before the timeout (" + rootCause(err) + ")"}
	}
	return &Error{Code: CodeUnreachable, Message: "could not reach the instance (" + rootCause(err) + ")"}
}

func isTimeout(err error) bool {
	var t interface{ Timeout() bool }
	return errors.As(err, &t) && t.Timeout()
}

// rootCause is the innermost message, which for a *url.Error drops the method
// and URL that Go prefixes (the URL is the operator's, but it adds nothing).
func rootCause(err error) string {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return err.Error()
		}
		err = u
	}
}

func snippet(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return ""
	}
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80]) + "…"
	}
	return ": " + s
}
