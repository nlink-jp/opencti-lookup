package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// isolate points every search root at a temp dir and clears every variable
// the loader reads, so no test sees the developer's real config.
func isolate(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	for _, v := range []string{"OPENCTI_LOOKUP_URL", "OPENCTI_LOOKUP_TOKEN", "OPENCTI_LOOKUP_CA_FILE",
		"OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY", "OPENCTI_LOOKUP_TIMEOUT_SECONDS"} {
		t.Setenv(v, "")
	}
	return home
}

func write(t *testing.T, path, body string, mode os.FileMode) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNoFileIsNotAnErrorButNotReady(t *testing.T) {
	isolate(t)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Path != "" || len(cfg.Searched) == 0 {
		t.Fatalf("Path=%q Searched=%v", cfg.Path, cfg.Searched)
	}
	err = cfg.Ready()
	if err == nil || !strings.Contains(err.Error(), "url") || !strings.Contains(err.Error(), "token") || !strings.Contains(err.Error(), "searched") {
		t.Fatalf("Ready() = %v; want both missing settings and the searched paths named", err)
	}
	if cfg.Timeout != DefaultTimeout || cfg.DefaultLimit != DefaultLimit || cfg.MaxLimit != DefaultMaxLimit {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestExplicitMissingFileIsAnError(t *testing.T) {
	isolate(t)
	missing := filepath.Join(t.TempDir(), "nope.toml")
	_, err := Load(missing, 0)
	if err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "--config") {
		t.Fatalf("Load(%q) = %v; want an error naming the path", missing, err)
	}
}

func TestSearchOrder(t *testing.T) {
	home := isolate(t)
	xdg := filepath.Join(home, "xdg")
	t.Setenv("XDG_CONFIG_HOME", xdg)
	dot := write(t, filepath.Join(home, ".config", AppName, "config.toml"), "[opencti]\nurl = \"https://dot.example\"\n", 0o600)

	paths := SearchPaths()
	if paths[0] != filepath.Join(xdg, AppName, "config.toml") || paths[1] != dot {
		t.Fatalf("SearchPaths() = %v", paths)
	}
	if runtime.GOOS == "darwin" && !strings.Contains(paths[len(paths)-1], filepath.Join("Library", "Application Support", AppName)) {
		t.Fatalf("Application Support is not searched: %v", paths)
	}
	// XDG is set but holds no file: ~/.config must still be read.
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != dot || cfg.URL != "https://dot.example" {
		t.Fatalf("read %q url %q; want %q", cfg.Path, cfg.URL, dot)
	}
	// The earlier root wins once it holds a file.
	xdgFile := write(t, filepath.Join(xdg, AppName, "config.toml"), "[opencti]\nurl = \"https://xdg.example\"\n", 0o600)
	cfg, err = Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != xdgFile || cfg.URL != "https://xdg.example" {
		t.Fatalf("read %q url %q; want %q", cfg.Path, cfg.URL, xdgFile)
	}
}

func TestApplicationSupportIsRead(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Application Support is a macOS location")
	}
	home := isolate(t)
	p := write(t, filepath.Join(home, "Library", "Application Support", AppName, "config.toml"), "[opencti]\ntoken = \"t\"\n", 0o600)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Path != p || cfg.Token != "t" {
		t.Fatalf("read %q token %q", cfg.Path, cfg.Token)
	}
}

func TestStrictFile(t *testing.T) {
	isolate(t)
	cases := []struct {
		name, body, want string
	}{
		{"unknown key", "[opencti]\nurl = \"https://x.example\"\napi_key = \"k\"\n", "opencti.api_key"},
		{"unknown table", "[cache]\nttl = 3\n", "cache.ttl"},
		{"top-level key", "token = \"t\"\n", "token"},
		{"empty url", "[opencti]\nurl = \"\"\n", "present but empty"},
		{"blank token", "[opencti]\ntoken = \"  \"\n", "present but empty"},
		{"timeout range", "[opencti]\ntimeout_seconds = 0\n", "timeout_seconds"},
		{"max over ceiling", "[query]\nmax_limit = 5001\n", "max_limit"},
		{"default over max", "[query]\nmax_limit = 10\ndefault_limit = 11\n", "default_limit"},
		{"wrong type", "[opencti]\ninsecure_skip_verify = \"yes\"\n", "insecure_skip_verify"},
		{"bad scheme", "[opencti]\nurl = \"ftp://x.example\"\n", "http or https"},
		{"user info", "[opencti]\nurl = \"https://u:p@x.example\"\n", "user info"},
		{"query", "[opencti]\nurl = \"https://x.example/?a=1\"\n", "user info"},
		{"syntax", "[opencti\n", "toml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := write(t, filepath.Join(t.TempDir(), "c.toml"), c.body, 0o600)
			_, err := Load(p, 0)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("Load = %v; want an error containing %q", err, c.want)
			}
		})
	}
}

func TestFullFileAndEnvPrecedence(t *testing.T) {
	isolate(t)
	p := write(t, filepath.Join(t.TempDir(), "c.toml"), `
[opencti]
url = "https://cti.example/opencti/"
token = "file-token"
insecure_skip_verify = true
timeout_seconds = 12

[query]
default_limit = 7
max_limit = 70
`, 0o600)
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://cti.example/opencti" || cfg.Token != "file-token" || !cfg.InsecureSkipVerify ||
		cfg.Timeout != 12*time.Second || cfg.DefaultLimit != 7 || cfg.MaxLimit != 70 {
		t.Fatalf("file not applied: %+v", cfg.Redacted())
	}

	t.Setenv("OPENCTI_LOOKUP_URL", "https://env.example")
	t.Setenv("OPENCTI_LOOKUP_TOKEN", "env-token")
	t.Setenv("OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY", "false")
	t.Setenv("OPENCTI_LOOKUP_TIMEOUT_SECONDS", "5")
	cfg, err = Load(p, 9*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URL != "https://env.example" || cfg.Token != "env-token" || cfg.InsecureSkipVerify || cfg.Timeout != 9*time.Second {
		t.Fatalf("precedence wrong: %+v", cfg.Redacted())
	}
	if err := cfg.Ready(); err != nil {
		t.Fatalf("Ready: %v", err)
	}
}

func TestBadEnvironment(t *testing.T) {
	for name, val := range map[string]string{
		"OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY": "maybe",
		"OPENCTI_LOOKUP_TIMEOUT_SECONDS":      "601",
		"OPENCTI_LOOKUP_URL":                  "not a url",
	} {
		t.Run(name, func(t *testing.T) {
			isolate(t)
			t.Setenv(name, val)
			if _, err := Load("", 0); err == nil {
				t.Fatalf("%s=%q was accepted", name, val)
			}
		})
	}
}

func TestPermissionWarning(t *testing.T) {
	isolate(t)
	open := write(t, filepath.Join(t.TempDir(), "c.toml"), "[opencti]\ntoken = \"t\"\n", 0o644)
	cfg, err := Load(open, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "permissions 0644; expected 0600.") {
		t.Fatalf("Warnings = %v", cfg.Warnings)
	}
	closed := write(t, filepath.Join(t.TempDir(), "c.toml"), "[opencti]\ntoken = \"t\"\n", 0o600)
	cfg, err = Load(closed, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("0600 file warned: %v", cfg.Warnings)
	}
}

func TestPlainHTTP(t *testing.T) {
	for url, plain := range map[string]bool{
		"https://cti.example":    false,
		"http://cti.example":     true,
		"http://10.0.0.5:8080":   true,
		"http://127.0.0.1:8080":  false,
		"http://localhost:8080":  false,
		"http://[::1]:8080/path": false,
	} {
		t.Run(url, func(t *testing.T) {
			isolate(t)
			t.Setenv("OPENCTI_LOOKUP_URL", url)
			cfg, err := Load("", 0)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.PlainHTTP() != plain {
				t.Fatalf("PlainHTTP() = %v", cfg.PlainHTTP())
			}
			warned := len(cfg.Warnings) == 1 && strings.Contains(cfg.Warnings[0], "plain http")
			if warned != plain {
				t.Fatalf("Warnings = %v", cfg.Warnings)
			}
		})
	}
}

func TestInsecureWarns(t *testing.T) {
	isolate(t)
	t.Setenv("OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY", "true")
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "verification is OFF") {
		t.Fatalf("Warnings = %v", cfg.Warnings)
	}
}

func TestCAFile(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	good := write(t, filepath.Join(dir, "ca.pem"), selfSignedPEM(t), 0o600)
	t.Setenv("OPENCTI_LOOKUP_CA_FILE", good)
	cfg, err := Load("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAPool == nil || cfg.CAFile != good {
		t.Fatalf("CA not loaded: %q", cfg.CAFile)
	}

	bad := write(t, filepath.Join(dir, "bad.pem"), "not a certificate", 0o600)
	t.Setenv("OPENCTI_LOOKUP_CA_FILE", bad)
	if _, err := Load("", 0); err == nil || !strings.Contains(err.Error(), "no PEM certificate") {
		t.Fatalf("bad CA accepted: %v", err)
	}
	t.Setenv("OPENCTI_LOOKUP_CA_FILE", filepath.Join(dir, "absent.pem"))
	if _, err := Load("", 0); err == nil {
		t.Fatal("missing CA accepted")
	}
}

func TestRedactedNeverHoldsTheToken(t *testing.T) {
	cfg := &Config{Token: "secret-token-value", URL: "https://x.example"}
	r := cfg.Redacted()
	if r.Token != redactedPlaceholder || cfg.Token != "secret-token-value" {
		t.Fatalf("Redacted: %q, original %q", r.Token, cfg.Token)
	}
	if (&Config{}).Redacted().Token != "" {
		t.Fatal("an unset token must stay empty, not look configured")
	}
}

func TestTimeoutOverrideRange(t *testing.T) {
	isolate(t)
	if _, err := Load("", 601*time.Second); err == nil {
		t.Fatal("--timeout 601 accepted")
	}
}

// The shipped example, with every setting uncommented, must load: an example
// that names a key the loader refuses teaches the operator an error.
func TestExampleConfigLoads(t *testing.T) {
	isolate(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "config.example.toml"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	uncommented := 0
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "#") && strings.Contains(l, " = ") && !strings.HasPrefix(l, "# ") {
			l = strings.TrimPrefix(l, "#")
			uncommented++
		}
		lines = append(lines, l)
	}
	if uncommented != 7 {
		t.Fatalf("uncommented %d settings; the example and this test disagree", uncommented)
	}
	dir := t.TempDir()
	body := strings.Join(lines, "\n")
	// The example's ca_file points at the operator's own certificate.
	ca := write(t, filepath.Join(dir, "ca.pem"), selfSignedPEM(t), 0o600)
	body = strings.Replace(body, `ca_file = "~/.config/opencti-lookup/opencti-ca.pem"`, `ca_file = "`+ca+`"`, 1)
	p := write(t, filepath.Join(dir, "config.toml"), body, 0o600)
	cfg, err := Load(p, 0)
	if err != nil {
		t.Fatalf("the uncommented example does not load: %v", err)
	}
	if cfg.URL != "https://opencti.example.org" || cfg.Token == "" || cfg.CAPool == nil || cfg.MaxLimit != 500 {
		t.Fatalf("%+v", cfg.Redacted())
	}
}

func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
