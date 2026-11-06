package opencti

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// withRisk is the one way an untrusted certificate can always be got past,
// and the price of it, said the same way in every message.
const withRisk = "or — knowing the token can then be read on the path — set insecure_skip_verify"

// certificateError explains a certificate this client refused, in terms of
// what the operator can do about it. ca_file only fixes an unknown issuer:
// a certificate that names its host only in the legacy Common Name, names
// another host, is out of date or is not for server use is refused whoever
// issued it, so for those the message says so instead of sending the
// operator to ca_file (measured on a production instance, 2026-11-07: a
// CN-only self-signed certificate first failed as "unknown authority", and
// only after ca_file was set did the real cause appear). The certificate the server presented is examined even when
// verification stopped at the issuer, so the real cause is named first time.
//
// host is the host the client connected to; ok is false when err is not a
// certificate refusal.
func certificateError(err error, host string) (*Error, bool) {
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError

	// Find the certificate the server presented, whichever error carries it.
	// Which error Go returns depends on the platform: on macOS, with no
	// ca_file, the system verifier reports an expired, not-yet-valid or
	// wrong-usage self-signed certificate as "unknown authority" too, so the
	// certificate itself is examined before any error type is trusted.
	isCert := false
	var leaf *x509.Certificate
	if errors.As(err, &verifyErr) {
		isCert = true
		if len(verifyErr.UnverifiedCertificates) > 0 {
			leaf = verifyErr.UnverifiedCertificates[0]
		}
	}
	if errors.As(err, &hostErr) {
		isCert = true
		if leaf == nil {
			leaf = hostErr.Certificate
		}
		if hostErr.Host != "" {
			host = hostErr.Host
		}
	}
	if errors.As(err, &invalid) {
		isCert = true
		if leaf == nil {
			leaf = invalid.Cert
		}
	}
	if errors.As(err, &unknownCA) {
		isCert = true
		if leaf == nil {
			leaf = unknownCA.Cert
		}
	}
	if !isCert {
		return nil, false
	}

	if leaf != nil {
		now := timeNow()
		switch {
		case now.Before(leaf.NotBefore):
			return certErr(err, fmt.Sprintf("it is not valid until %s — check this machine's clock first; ca_file cannot fix that. "+
				"If the clock is right, ask the instance's operator for a certificate valid now, %s",
				leaf.NotBefore.UTC().Format("2006-01-02 15:04 MST"), withRisk)), true
		case now.After(leaf.NotAfter):
			return certErr(err, fmt.Sprintf("it expired on %s; ca_file cannot fix that. Ask the instance's operator for a renewed certificate, %s",
				leaf.NotAfter.UTC().Format("2006-01-02"), withRisk)), true
		case len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0:
			return certErr(err, fmt.Sprintf("it names its host only in the legacy Common Name field (CN=%s) and carries no subjectAltName, "+
				"which Go refuses whoever issued it, so ca_file cannot fix that. Ask the instance's operator for a certificate with a "+
				"subjectAltName for %s (%s), %s",
				leaf.Subject.CommonName, host, sanFor(host), withRisk)), true
		case host != "" && leaf.VerifyHostname(host) != nil:
			return certErr(err, fmt.Sprintf("it is for %s, not %s, so ca_file cannot fix that. Use a URL with one of those names, "+
				"ask for a certificate that includes %s, %s",
				strings.Join(certNames(leaf), ", "), host, host, withRisk)), true
		case !forServers(leaf):
			return certErr(err, "it is not issued for use by a server (its extended key usage lacks serverAuth), so ca_file cannot fix that. "+
				"Ask the instance's operator for a server certificate, "+withRisk), true
		}
	}
	// The certificate itself is in order (or was not available): what is
	// left is trust in its issuer — a self-signed certificate, an internal CA,
	// or an intermediate the server did not send.
	switch {
	case invalid.Reason == x509.IncompatibleUsage && invalid.Cert != nil:
		return certErr(err, "a certificate in its chain is not issued for this use, so ca_file cannot fix that. "+
			"Ask the instance's operator for a server certificate, "+withRisk), true
	case invalid.Reason == x509.Expired && invalid.Cert != nil:
		return certErr(err, "a certificate in its chain is outside its validity period — check this machine's clock first; "+
			"ca_file cannot fix that. Ask the instance's operator for a renewed chain, "+withRisk), true
	}
	return certErr(err, "its issuer is not trusted here: set ca_file to the certificate (a self-signed one) or to the CA that issued it "+
		"(an internal CA), "+withRisk), true
}

// forServers reports whether a certificate may be presented by a server: no
// extended key usage at all (any use), or one that includes serverAuth or any.
func forServers(c *x509.Certificate) bool {
	if len(c.ExtKeyUsage) == 0 && len(c.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth || u == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// timeNow is replaced in tests.
var timeNow = time.Now

func certErr(err error, advice string) *Error {
	return &Error{Code: CodeUnreachable, Message: "the instance's TLS certificate was not accepted (" + rootCause(err) + "): " + advice}
}

// sanFor says which subjectAltName entry the host needs.
func sanFor(host string) string {
	h := strings.Trim(host, "[]")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i] // an IPv6 zone is not part of the address a certificate names
	}
	if ip := net.ParseIP(h); ip != nil {
		return "IP:" + ip.String()
	}
	return "DNS:" + host
}

func certNames(c *x509.Certificate) []string {
	names := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	return names
}
