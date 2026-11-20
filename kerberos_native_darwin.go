//go:build darwin

package kpx

import (
	"encoding/base64"
	"net"
	"strings"

	_ "github.com/golang-auth/go-gssapi-c"
	"github.com/golang-auth/go-gssapi/v3"
	"github.com/palantir/stacktrace"
)

var NativeKerberos = &DarwinKerberos{}
var gss = gssapi.MustNewProvider("github.com/golang-auth/go-gssapi-c")

type DarwinKerberos struct {
}

func (k *DarwinKerberos) SafeTryLogin() error {
	logInfo("[-] Authenticating user with macOS native kerberos")

	_, err := gss.AcquireCredential(
		nil, // current user
		nil, // default mech
		gssapi.CredUsageInitiateOnly,
		nil,
	)
	if err != nil {
		return stacktrace.Propagate(err,
			"unable to acquire kerberos credentials from macOS")
	}

	return nil
}

func (k *DarwinKerberos) SafeGetToken(
	protocol string,
	host string,
) (*string, error) {

	cname, err := k.getCanonicalHostname(host)
	if err != nil {
		return nil, stacktrace.Propagate(err,
			"unable to resolve host from hostname: %s",
			host)
	}

	spn := protocol + "/" + cname

	target, err := gss.ImportName(
		spn,
		gssapi.GSS_KRB5_NT_PRINCIPAL_NAME,
	)
	if err != nil {
		return nil, stacktrace.Propagate(err,
			"unable to import service name %s",
			spn)
	}

	cred, err := gss.AcquireCredential(
		nil, // current user
		nil, // default mech
		gssapi.CredUsageInitiateOnly,
		nil,
	)
	if err != nil {
		return nil, stacktrace.Propagate(err,
			"unable to acquire kerberos credentials from macOS")
	}
	defer cred.Release()

	logInfo("host=%s", host)
	logInfo("cname=%s", cname)
	logInfo("spn=%s", spn)

	ctx, err := gss.InitSecContext(
		target,
		gssapi.WithInitiatorCredential(cred))
	if err != nil {
		return nil, stacktrace.Propagate(err,
			"unable to initialize security context for %s",
			spn)
	}

	token, _, err := ctx.Continue(nil)
	if err != nil {
		return nil, stacktrace.Propagate(err,
			"unable to initialize security context for %s",
			spn)
	}

	hs := base64.StdEncoding.EncodeToString(token)
	return &hs, nil
}

func (k *DarwinKerberos) getCanonicalHostname(
	hostname string,
) (string, error) {

	cname, err := net.LookupCNAME(hostname)
	if err != nil {
		return "", err
	}

	return strings.TrimRight(cname, "."), nil
}
