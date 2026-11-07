// Package config resolves opencti-lookup's settings from flags, environment
// variables and a TOML file, in that order of precedence.
//
// The file is read with nlink-jp/toml (organization ADR-026) and strictly:
// an unknown key is an error that names it, a present-but-empty value is an
// error, a number out of range is an error, and a file named with --config
// that does not exist is an error. Input that is not understood is refused,
// never ignored.
//
// Loading succeeds without a URL or a token, so that the MCP handshake and
// get_usage work before the operator has configured anything; Ready reports
// what is missing, and every query checks it first.
package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/nlink-jp/toml"
)

// AppName is the directory name under every config search root.
const AppName = "opencti-lookup"

// Defaults and bounds.
const (
	DefaultTimeout      = 30 * time.Second
	MaxTimeoutSeconds   = 600
	DefaultLimit        = 25
	DefaultMaxLimit     = 500
	OpenCTIPageCeiling  = 5000 // measured: OpenCTI silently cuts first above this
	redactedPlaceholder = "[redacted]"
)

// Config holds resolved runtime settings.
type Config struct {
	URL                string // the instance's base URL, without a trailing slash
	Token              string
	CAFile             string
	CAPool             *x509.CertPool // nil unless CAFile is set
	InsecureSkipVerify bool
	Timeout            time.Duration
	DefaultLimit       int
	MaxLimit           int

	// Path is the config file actually read, "" when none was.
	Path string
	// Searched lists where a file was looked for when none was named.
	Searched []string
	// Warnings are conditions the operator should see once, on stderr.
	Warnings []string
}

// fileConfig mirrors the TOML document. Pointers tell "absent" from "set".
type fileConfig struct {
	OpenCTI struct {
		URL                *string `toml:"url"`
		Token              *string `toml:"token"`
		CAFile             *string `toml:"ca_file"`
		InsecureSkipVerify *bool   `toml:"insecure_skip_verify"`
		TimeoutSeconds     *int    `toml:"timeout_seconds"`
	} `toml:"opencti"`
	Query struct {
		DefaultLimit *int `toml:"default_limit"`
		MaxLimit     *int `toml:"max_limit"`
	} `toml:"query"`
}

// Load resolves configuration. configPath is the --config flag ("" when not
// given); timeoutOverride is the --timeout flag (0 when not given).
func Load(configPath string, timeoutOverride time.Duration) (*Config, error) {
	cfg := &Config{Timeout: DefaultTimeout, DefaultLimit: DefaultLimit, MaxLimit: DefaultMaxLimit}

	path := configPath
	if path == "" {
		cfg.Searched = SearchPaths()
		path = firstExisting(cfg.Searched)
	} else {
		path = expandHome(path)
	}
	if path != "" {
		if err := cfg.readFile(path, configPath != ""); err != nil {
			return nil, err
		}
	}
	if err := cfg.applyEnv(); err != nil {
		return nil, err
	}
	if timeoutOverride != 0 {
		if timeoutOverride < time.Second || timeoutOverride > MaxTimeoutSeconds*time.Second {
			return nil, fmt.Errorf("--timeout must be 1-%d seconds", MaxTimeoutSeconds)
		}
		cfg.Timeout = timeoutOverride
	}
	if err := cfg.finish(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (cfg *Config) readFile(path string, explicit bool) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && explicit {
			return fmt.Errorf("config file %s does not exist (named with --config)", path)
		}
		return fmt.Errorf("config file %s: %w", path, err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		cfg.Warnings = append(cfg.Warnings, fmt.Sprintf("config file %s has permissions %04o; expected 0600.", path, perm))
	}

	var fc fileConfig
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		var unknown *toml.UnknownKeysError
		if errors.As(err, &unknown) {
			names := make([]string, len(unknown.Keys))
			for i, k := range unknown.Keys {
				names[i] = k.String()
			}
			return fmt.Errorf("config file %s: unknown key(s): %s (known: [opencti] url, token, ca_file, insecure_skip_verify, timeout_seconds; [query] default_limit, max_limit)",
				path, strings.Join(names, ", "))
		}
		return fmt.Errorf("config file %s: %s", path, describeTOMLError(err))
	}
	cfg.Path = path

	o := fc.OpenCTI
	for _, s := range []struct {
		name string
		val  *string
		dst  *string
	}{
		{"[opencti] url", o.URL, &cfg.URL},
		{"[opencti] token", o.Token, &cfg.Token},
		{"[opencti] ca_file", o.CAFile, &cfg.CAFile},
	} {
		if s.val == nil {
			continue
		}
		if strings.TrimSpace(*s.val) == "" {
			return fmt.Errorf("config file %s: %s is present but empty (remove the line to leave it unset)", path, s.name)
		}
		*s.dst = strings.TrimSpace(*s.val)
	}
	if o.InsecureSkipVerify != nil {
		cfg.InsecureSkipVerify = *o.InsecureSkipVerify
	}
	if o.TimeoutSeconds != nil {
		if *o.TimeoutSeconds < 1 || *o.TimeoutSeconds > MaxTimeoutSeconds {
			return fmt.Errorf("config file %s: [opencti] timeout_seconds must be 1-%d", path, MaxTimeoutSeconds)
		}
		cfg.Timeout = time.Duration(*o.TimeoutSeconds) * time.Second
	}
	if v := fc.Query.MaxLimit; v != nil {
		cfg.MaxLimit = *v
	}
	if v := fc.Query.DefaultLimit; v != nil {
		cfg.DefaultLimit = *v
	}
	return nil
}

// describeTOMLError says where the file is wrong without quoting what is
// there: the decoder's own messages quote the offending token (up to 40
// characters), and the token may be the OpenCTI token written without quotes.
func describeTOMLError(err error) string {
	var pe *toml.ParseError
	if errors.As(err, &pe) {
		return fmt.Sprintf("not valid TOML at line %d, column %d (the text is not shown: it may hold the token — check the quoting there)", pe.Line, pe.Column)
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		return fmt.Sprintf("line %d: a value of the wrong type (strings are quoted, numbers and true/false are not)", de.Line)
	}
	return "not valid TOML (details withheld: they may quote the token)"
}

func (cfg *Config) applyEnv() error {
	if v, ok := env("OPENCTI_LOOKUP_URL"); ok {
		cfg.URL = v
	}
	if v, ok := env("OPENCTI_LOOKUP_TOKEN"); ok {
		cfg.Token = v
	}
	if v, ok := env("OPENCTI_LOOKUP_CA_FILE"); ok {
		cfg.CAFile = v
	}
	if v, ok := env("OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("OPENCTI_LOOKUP_INSECURE_SKIP_VERIFY must be true or false, got %q", v)
		}
		cfg.InsecureSkipVerify = b
	}
	if v, ok := env("OPENCTI_LOOKUP_TIMEOUT_SECONDS"); ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxTimeoutSeconds {
			return fmt.Errorf("OPENCTI_LOOKUP_TIMEOUT_SECONDS must be 1-%d, got %q", MaxTimeoutSeconds, v)
		}
		cfg.Timeout = time.Duration(n) * time.Second
	}
	return nil
}

// env returns a variable's value when it is set and not blank. A variable set
// to an empty string is treated as unset, as shells commonly leave them.
func env(name string) (string, bool) {
	v := strings.TrimSpace(os.Getenv(name))
	return v, v != ""
}

// finish validates the merged settings and derives what depends on them.
func (cfg *Config) finish() error {
	if cfg.MaxLimit < 1 || cfg.MaxLimit > OpenCTIPageCeiling {
		return fmt.Errorf("[query] max_limit must be 1-%d (OpenCTI returns at most %d rows per page)", OpenCTIPageCeiling, OpenCTIPageCeiling)
	}
	if cfg.DefaultLimit < 1 || cfg.DefaultLimit > cfg.MaxLimit {
		return fmt.Errorf("[query] default_limit must be 1-%d (max_limit)", cfg.MaxLimit)
	}
	if cfg.URL != "" {
		u, err := validateURL(cfg.URL)
		if err != nil {
			return err
		}
		cfg.URL = u
		if cfg.PlainHTTP() {
			cfg.Warnings = append(cfg.Warnings, "the OpenCTI URL is plain http: the token travels unencrypted on every request.")
		}
	}
	if cfg.InsecureSkipVerify {
		cfg.Warnings = append(cfg.Warnings, "TLS certificate verification is OFF (insecure_skip_verify): anyone on the path can read the token.")
	}
	if cfg.CAFile != "" {
		path := expandHome(cfg.CAFile)
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("ca_file %s: %w", path, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("ca_file %s holds no PEM certificate", path)
		}
		cfg.CAFile, cfg.CAPool = path, pool
	}
	return nil
}

// validateURL accepts an http or https URL with a host, and nothing that would
// smuggle a credential or change the request: no user info, query or fragment.
// A path is kept (an instance may live under one); a trailing slash is not.
func validateURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("[opencti] url: %v", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("[opencti] url must be http or https, got %q", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("[opencti] url has no host: %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("[opencti] url must not carry user info, a query or a fragment")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// PlainHTTP reports whether the token would travel unencrypted to another
// machine: an http URL whose host is not a loopback address.
func (cfg *Config) PlainHTTP() bool {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Scheme != "http" {
		return false
	}
	return !isLoopback(u.Hostname())
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Ready reports what keeps the tool from querying: a missing URL or token.
func (cfg *Config) Ready() error {
	var missing []string
	if cfg.URL == "" {
		missing = append(missing, "[opencti] url (or OPENCTI_LOOKUP_URL)")
	}
	if cfg.Token == "" {
		missing = append(missing, "[opencti] token (or OPENCTI_LOOKUP_TOKEN)")
	}
	if len(missing) == 0 {
		return nil
	}
	where := "no config file was found"
	if cfg.Path != "" {
		where = "read " + cfg.Path
	}
	return &NotConfiguredError{Missing: missing, Where: where, Searched: cfg.Searched}
}

// NotConfiguredError says what is missing and where the tool looked.
type NotConfiguredError struct {
	Missing  []string
	Where    string
	Searched []string
}

func (e *NotConfiguredError) Error() string {
	msg := "not configured: set " + strings.Join(e.Missing, " and ") + " (" + e.Where
	if len(e.Searched) > 0 {
		msg += "; searched " + strings.Join(e.Searched, ", ")
	}
	return msg + ")"
}

// Redacted returns the settings with the token replaced by a fixed marker, for
// anything that prints or serialises them.
func (cfg *Config) Redacted() Config {
	c := *cfg
	if c.Token != "" {
		c.Token = redactedPlaceholder
	}
	c.CAPool = nil
	return c
}

// SearchPaths lists where a config file is looked for, in order. macOS has two
// conventions and CLI users expect ~/.config there too, so both are searched —
// and ~/.config is searched even when XDG_CONFIG_HOME is set, because a file
// that exists and is silently not read is worse than none.
func SearchPaths() []string {
	var paths []string
	if x := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); x != "" {
		paths = append(paths, filepath.Join(x, AppName, "config.toml"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		dot := filepath.Join(home, ".config", AppName, "config.toml")
		if len(paths) == 0 || paths[0] != dot {
			paths = append(paths, dot)
		}
		if runtime.GOOS == "darwin" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", AppName, "config.toml"))
		}
	}
	return paths
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}
