package x

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
)

const (
	AppSSLCert = "app_ssl_certificate"
	AppSSLKey  = "app_ssl_certificate_key"
	RdsSSLCert = "rds_sslca"
)

func FixPemFormat(pem string) string {
	// First ensure "\\n" around header and footer become "\n"
	pem = strings.ReplaceAll(pem, "-----\\n", "-----\n")
	pem = strings.ReplaceAll(pem, "\\n-----", "\n-----")
	// Then the remaining "\\n" are inside the base64 encoded string. So remove them.
	return strings.ReplaceAll(pem, "\\n", "")
}

func RegisterMysqlTLS(certs string) error {
	rootCertPool := x509.NewCertPool()
	pem := []byte(certs)
	if ok := rootCertPool.AppendCertsFromPEM(pem); !ok {
		return errors.New("MySQL failed to append PEM")
	}
	return mysql.RegisterTLSConfig("custom", &tls.Config{RootCAs: rootCertPool})
}
