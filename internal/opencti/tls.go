package opencti

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// withRisk is the one way an untrusted certificate can always be got past,
// and the price of it, said the same way in every message.
const withRisk = "or — knowing the token can then be read on the path — set insecure_skip_verify"

// certificateError explains a certificate this client refused, in terms of
// what the operator can do about it. ca_file only fixes an unknown issuer:
// a certificate that names its host only in the legacy Common Name, names
// another host, or has expired is refused whoever issued it, so for those the
// message says so instead of sending the operator to ca_file (measured on a
// production instance, 2026-11-07: a CN-only self-signed certificate first
// failed as "unknown authority", and only after ca_file was set did the real
// cause appear). The certificate the server presented is examined even when
// verification stopped at the issuer, so the real cause is named first time.
//
// host is the host the client connected to; ok is false when err is not a
// certificate refusal.
func certificateError(err error, host string) (*Error, bool) {
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError

	var leaf *x509.Certificate
	if errors.As(err, &verifyErr) && len(verifyErr.UnverifiedCertificates) > 0 {
		leaf = verifyErr.UnverifiedCertificates[0]
	}
	switch {
	case errors.As(err, &hostErr):
		if hostErr.Certificate != nil {
			leaf = hostErr.Certificate
		}
		if hostErr.Host != "" {
			host = hostErr.Host
		}
	case errors.As(err, &invalid):
		if invalid.Cert != nil {
			leaf = invalid.Cert
		}
		if invalid.Reason == x509.Expired && leaf != nil {
			return certErr(err, fmt.Sprintf("it expired on %s; ca_file cannot fix that. Ask the instance's operator for a renewed certificate, %s",
				leaf.NotAfter.UTC().Format("2006-01-02"), withRisk)), true
		}
	case errors.As(err, &unknownCA):
		if unknownCA.Cert != nil {
			leaf = unknownCA.Cert
		}
	case verifyErr == nil:
		return nil, false
	}

	if leaf != nil {
		if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
			return certErr(err, fmt.Sprintf("it names its host only in the legacy Common Name field (CN=%s) and carries no subjectAltName, "+
				"which Go refuses whoever issued it, so ca_file cannot fix that. Ask the instance's operator for a certificate with a "+
				"subjectAltName for %s (%s), %s",
				leaf.Subject.CommonName, host, sanFor(host), withRisk)), true
		}
		if host != "" && leaf.VerifyHostname(host) != nil {
			return certErr(err, fmt.Sprintf("it is for %s, not %s, so ca_file cannot fix that. Use a URL with one of those names, "+
				"ask for a certificate that includes %s, %s",
				strings.Join(certNames(leaf), ", "), host, host, withRisk)), true
		}
	}
	if errors.As(err, &unknownCA) {
		return certErr(err, "its issuer is not trusted here: set ca_file to the certificate (a self-signed one) or to the CA that issued it "+
			"(an internal CA), "+withRisk), true
	}
	return certErr(err, "set ca_file to the certificate or its issuer if the issuer is the problem, "+withRisk), true
}

func certErr(err error, advice string) *Error {
	return &Error{Code: CodeUnreachable, Message: "the instance's TLS certificate was not accepted (" + rootCause(err) + "): " + advice}
}

// sanFor says which subjectAltName entry the host needs.
func sanFor(host string) string {
	if strings.Trim(host, "0123456789.:abcdefABCDEF[]") == "" && strings.ContainsAny(host, ".:") {
		return "IP:" + strings.Trim(host, "[]")
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
