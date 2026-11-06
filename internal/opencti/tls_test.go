package opencti

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nlink-jp/opencti-lookup/internal/config"
)

type certSpec struct {
	cn       string
	dns      []string
	ips      []net.IP
	notAfter time.Time
	eku      []x509.ExtKeyUsage // nil means serverAuth
}

// serveWith starts a TLS server presenting a self-signed certificate made
// from spec, and returns its URL and a pool that trusts that certificate.
func serveWith(t *testing.T, spec certSpec) (string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := spec.notAfter
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}
	eku := spec.eku
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spec.cn, Organization: []string{"Internet Widgits Pty Ltd"}},
		NotBefore:    notAfter.Add(-48 * time.Hour), NotAfter: notAfter,
		DNSNames: spec.dns, IPAddresses: spec.ips,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: eku,
		IsCA:        true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"data":{"about":{"version":"6.7.4"}}}`)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return srv.URL, pool
}

func ask(url string, pool *x509.CertPool, insecure bool) error {
	c := New(&config.Config{URL: url, Token: testToken, Timeout: 5 * time.Second, CAPool: pool, InsecureSkipVerify: insecure})
	return c.Query(context.Background(), "{ about { version } }", nil, nil)
}

// The production case (2026-11-07): a self-signed certificate naming its host
// only in the Common Name. ca_file must not be offered as the fix — neither
// before it is set (the error is "unknown authority") nor after (the error
// becomes the legacy-CN refusal).
func TestCommonNameOnlyCertificate(t *testing.T) {
	url, pool := serveWith(t, certSpec{cn: "127.0.0.1"})
	for name, p := range map[string]*x509.CertPool{"without ca_file": nil, "with ca_file": pool} {
		err := ask(url, p, false)
		msg := err.Error()
		if Code(err) != CodeUnreachable || !strings.Contains(msg, "legacy Common Name field (CN=127.0.0.1)") ||
			!strings.Contains(msg, "ca_file cannot fix that") || !strings.Contains(msg, "IP:127.0.0.1") ||
			!strings.Contains(msg, "insecure_skip_verify") || strings.Contains(msg, "set ca_file to") {
			t.Errorf("%s: %s", name, msg)
		}
	}
	if err := ask(url, nil, true); err != nil {
		t.Fatalf("insecure_skip_verify must still connect: %v", err)
	}
}

func TestCertificateForAnotherName(t *testing.T) {
	url, pool := serveWith(t, certSpec{cn: "cti.example", dns: []string{"cti.example", "opencti.example"}})
	for name, p := range map[string]*x509.CertPool{"without ca_file": nil, "with ca_file": pool} {
		msg := ask(url, p, false).Error()
		if !strings.Contains(msg, "it is for cti.example, opencti.example, not 127.0.0.1") || !strings.Contains(msg, "ca_file cannot fix that") ||
			strings.Contains(msg, "set ca_file to") {
			t.Errorf("%s: %s", name, msg)
		}
	}
}

// Each refusal below is one ca_file cannot fix, so it must be named on the
// first attempt too — on macOS the system verifier reports all of them as
// "unknown authority" while no ca_file is set.
func TestExpiredCertificate(t *testing.T) {
	expiry := time.Now().Add(-24 * time.Hour)
	url, pool := serveWith(t, certSpec{cn: "127.0.0.1", ips: []net.IP{net.ParseIP("127.0.0.1")}, notAfter: expiry})
	for name, p := range map[string]*x509.CertPool{"without ca_file": nil, "with ca_file": pool} {
		msg := ask(url, p, false).Error()
		if !strings.Contains(msg, "expired on "+expiry.UTC().Format("2006-01-02")) || !strings.Contains(msg, "ca_file cannot fix that") ||
			strings.Contains(msg, "set ca_file to") {
			t.Errorf("%s: %s", name, msg)
		}
	}
}

// A certificate whose validity has not begun is not "expired": the likelier
// cause is this machine's clock.
func TestNotYetValidCertificate(t *testing.T) {
	notAfter := time.Now().Add(72 * time.Hour) // serveWith starts validity 48h earlier: tomorrow
	url, pool := serveWith(t, certSpec{cn: "127.0.0.1", ips: []net.IP{net.ParseIP("127.0.0.1")}, notAfter: notAfter})
	for name, p := range map[string]*x509.CertPool{"without ca_file": nil, "with ca_file": pool} {
		msg := ask(url, p, false).Error()
		if !strings.Contains(msg, "it is not valid until "+notAfter.Add(-48*time.Hour).UTC().Format("2006-01-02")) ||
			!strings.Contains(msg, "check this machine's clock") || strings.Contains(msg, "it expired on") ||
			strings.Contains(msg, "set ca_file to") {
			t.Errorf("%s: %s", name, msg)
		}
	}
}

func TestClientOnlyCertificate(t *testing.T) {
	url, pool := serveWith(t, certSpec{cn: "127.0.0.1", ips: []net.IP{net.ParseIP("127.0.0.1")},
		eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	for name, p := range map[string]*x509.CertPool{"without ca_file": nil, "with ca_file": pool} {
		msg := ask(url, p, false).Error()
		if !strings.Contains(msg, "not issued for use by a server") || !strings.Contains(msg, "ca_file cannot fix that") ||
			strings.Contains(msg, "set ca_file to") {
			t.Errorf("%s: %s", name, msg)
		}
	}
}

// The validity checks read the clock through timeNow; a certificate that is
// in date by it is judged on its other merits.
func TestValidityUsesTimeNow(t *testing.T) {
	leaf := &x509.Certificate{NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2026, 12, 12, 0, 0, 0, 0, time.UTC),
		IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}
	defer func(f func() time.Time) { timeNow = f }(timeNow)
	for now, want := range map[time.Time]string{
		time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC): "it is not valid until 2026-01-01",
		time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC): "it expired on 2026-12-12",
		time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC): "its issuer is not trusted here",
	} {
		timeNow = func() time.Time { return now }
		e, ok := certificateError(x509.UnknownAuthorityError{Cert: leaf}, "192.0.2.1")
		if !ok || !strings.Contains(e.Message, want) {
			t.Errorf("at %s: %v, want %q", now.Format("2006-01-02"), e, want)
		}
	}
}

func TestNotACertificateError(t *testing.T) {
	if _, ok := certificateError(io.ErrUnexpectedEOF, "192.0.2.1"); ok {
		t.Fatal("a non-certificate error was explained as one")
	}
}

// Only an untrusted issuer, everything else in order: this is what ca_file fixes.
func TestUntrustedButOtherwiseValidCertificate(t *testing.T) {
	url, pool := serveWith(t, certSpec{cn: "127.0.0.1", ips: []net.IP{net.ParseIP("127.0.0.1")}})
	msg := ask(url, nil, false).Error()
	if !strings.Contains(msg, "its issuer is not trusted here: set ca_file to the certificate") {
		t.Fatalf("%s", msg)
	}
	if err := ask(url, pool, false); err != nil {
		t.Fatalf("with ca_file: %v", err)
	}
}

func TestSANFor(t *testing.T) {
	for host, want := range map[string]string{
		"18.181.0.1":      "IP:18.181.0.1",
		"2001:db8::1":     "IP:2001:db8::1",
		"[2001:db8::1]":   "IP:2001:db8::1",
		"cti.example.org": "DNS:cti.example.org",
		"deadbeef":        "DNS:deadbeef",
		"cafe.be":         "DNS:cafe.be",
		"abc.de":          "DNS:abc.de",
		"dead.beef":       "DNS:dead.beef",
		"fe80::1%en0":     "IP:fe80::1",
		"[fe80::1%en0]":   "IP:fe80::1",
	} {
		if got := sanFor(host); got != want {
			t.Errorf("sanFor(%q) = %q, want %q", host, got, want)
		}
	}
}
