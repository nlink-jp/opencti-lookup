package opencti

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// More codes, for the storage endpoint.
const (
	// CodeNotFound: the file does not exist, or this key may not see it —
	// the storage endpoint answers both with the same 503 (Phase 0 §7).
	CodeNotFound = "not_found"
	// CodeFileTooLarge: the file is larger than this tool will save.
	CodeFileTooLarge = "file_too_large"
)

// Download streams one stored file (an id such as
// "import/Report/<id>/<name>") to w, refusing more than max bytes. It returns
// the bytes written and the Content-Type the instance sent.
//
// Storage answers outside GraphQL, with its own statuses (measured on 6.7.4):
// 200 with the body; 403 with a plain "Forbidden" for a refused token; 503
// with {"status":"error","error":"File not found or restricted"} for a file
// that is absent or that this key may not see.
func (c *Client) Download(ctx context.Context, fileID string, w io.Writer, max int64) (int64, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/storage/get/"+url.PathEscape(fileID), nil)
	if err != nil {
		return 0, "", &Error{Code: CodeUnreachable, Message: "build request: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", transportError(err, c.host)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return 0, "", &Error{Code: CodeUnreachable, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(
			"the instance answered the download with a redirect (HTTP %d), which this tool does not follow", resp.StatusCode)}
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return 0, "", &Error{Code: CodeAuthFailed, HTTPStatus: resp.StatusCode, Message: "the instance refused the token for the download: check token"}
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusServiceUnavailable && strings.Contains(string(body), "not found or restricted") {
			return 0, "", &Error{Code: CodeNotFound, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf(
				"file %q is not there, or this key may not see it (the instance answers both alike)", fileID)}
		}
		return 0, "", &Error{Code: CodeUpstreamError, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("HTTP %d from the instance's storage%s", resp.StatusCode, snippet(body))}
	}

	n, err := io.Copy(w, io.LimitReader(resp.Body, max+1))
	if err != nil {
		return n, "", &Error{Code: CodeUnreachable, HTTPStatus: resp.StatusCode, Message: "download interrupted: " + err.Error()}
	}
	if n > max {
		return n, "", &Error{Code: CodeFileTooLarge, HTTPStatus: resp.StatusCode, Message: fmt.Sprintf("the file is larger than %d MB, which this tool does not save", max>>20)}
	}
	return n, resp.Header.Get("Content-Type"), nil
}
