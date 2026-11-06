//go:build e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The built binary, driven as an operator and as an MCP client would, against
// the development stack — the layers above the engine that the engine tests
// do not reach: config resolution, the CLI, stdio JSON-RPC.

func binary(t *testing.T) string {
	t.Helper()
	b := os.Getenv("OPENCTI_E2E_BINARY")
	if b == "" {
		t.Fatal("OPENCTI_E2E_BINARY must be set (run make e2e)")
	}
	return b
}

// configFile writes a 0600 config for the read-only user and returns its path.
func configFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	body := fmt.Sprintf("[opencti]\nurl = %q\ntoken = %q\n", os.Getenv("OPENCTI_E2E_URL"), os.Getenv("OPENCTI_E2E_READONLY_TOKEN"))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// command runs the binary with an environment that cannot leak the
// developer's own config into the test.
func command(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(binary(t), args...)
	home := t.TempDir()
	cmd.Env = []string{"HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, "xdg"), "PATH=" + os.Getenv("PATH")}
	return cmd
}

func TestBinaryCLI(t *testing.T) {
	cfg := configFile(t)
	out, err := command(t, "ioc", "192.0.2.10", "orphan.example.org", "--json", "--config", cfg).Output()
	if err != nil {
		t.Fatalf("ioc: %v", err)
	}
	var res struct {
		Results []struct {
			Input string `json:"input"`
			Found bool   `json:"found"`
		} `json:"results"`
	}
	if err := json.Unmarshal(out, &res); err != nil || len(res.Results) != 2 || !res.Results[0].Found || !res.Results[1].Found {
		t.Fatalf("%v %s", err, out)
	}

	out, err = command(t, "status", "-c", cfg).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "opencti-lookup-readonly") || !strings.Contains(string(out), "matches the verified version") {
		t.Fatalf("status: %v\n%s", err, out)
	}

	cmd := command(t, "ioc", "192.0.2.10")
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
		t.Fatalf("no config must exit 2 (not configured): %v", err)
	}
}

func TestBinaryMCP(t *testing.T) {
	cmd := command(t, "mcp", "--config", configFile(t))
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)

	call := func(id int, method string, params any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		if _, err := stdin.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
		done := make(chan bool, 1)
		go func() { done <- sc.Scan() }()
		select {
		case ok := <-done:
			if !ok {
				t.Fatalf("no reply to %s: %v", method, sc.Err())
			}
		case <-time.After(60 * time.Second):
			t.Fatalf("timeout waiting for %s", method)
		}
		var reply map[string]any
		if err := json.Unmarshal(sc.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}

	if r := call(1, "initialize", map[string]any{}); r["result"] == nil {
		t.Fatalf("initialize: %v", r)
	}
	tool := func(id int, name string, args any) (string, bool) {
		r := call(id, "tools/call", map[string]any{"name": name, "arguments": args})
		res := r["result"].(map[string]any)
		isErr, _ := res["isError"].(bool)
		return res["content"].([]any)[0].(map[string]any)["text"].(string), isErr
	}
	text, isErr := tool(2, "lookup_ioc", map[string]any{"values": []string{"2001:db8::20", "198.51.100.7"}})
	if isErr || !strings.Contains(text, `"match": "equivalent"`) || !strings.Contains(text, "not visible to this key") {
		t.Fatalf("lookup_ioc: %s", text)
	}
	text, isErr = tool(3, "search_threats", map[string]any{"query": "T1566", "types": []string{"attack-pattern"}})
	if isErr || !strings.Contains(text, `"mode": "exact"`) {
		t.Fatalf("search_threats: %s", text)
	}
	text, isErr = tool(4, "get_related", map[string]any{"id": "00000000-0000-4000-8000-000000000000"})
	if !isErr || !strings.Contains(text, `"not_found"`) {
		t.Fatalf("get_related on a missing id: %s", text)
	}
	text, isErr = tool(5, "server_status", map[string]any{})
	if isErr || !strings.Contains(text, `"version_matches": true`) || !strings.Contains(text, `"KNOWLEDGE"`) {
		t.Fatalf("server_status: %s", text)
	}
}
