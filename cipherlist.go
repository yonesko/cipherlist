package main

// Using go:linkname requires us to import unsafe
import (
	"crypto/tls"
	"net"
	"sync"
	_ "unsafe"

	"golang.org/x/sync/errgroup"
)

// We bring the real defaultCipherSuitesTLS13 function from the
// crypto/tls package into our own package.  This lets us perform
// that lazy initialization of the cipher list when we want.

//go:linkname defaultCipherSuitesTLS13 crypto/tls.defaultCipherSuitesTLS13
func defaultCipherSuitesTLS13() []uint16

// Next we bring the `varDefaultCipherSuitesTLS13` slice into our
// package.  This is what we manipulate to get the cipher suites.

//go:linkname varDefaultCipherSuitesTLS13 crypto/tls.varDefaultCipherSuitesTLS13
var varDefaultCipherSuitesTLS13 []uint16

// Also keep a variable around for the real default set, so we
// can reset it once we're finished.
var realDefaultCipherSuitesTLS13 []uint16

func init() {
	// Initialize the TLS 1.3 ciphersuite set; this populates
	// varDefaultCipherSuitesTLS13 under the covers
	realDefaultCipherSuitesTLS13 = defaultCipherSuitesTLS13()
}

func SupportedTLS13Ciphers(hostname string) ([]uint16, error) {
	supportedCiphersLock := sync.Mutex{}
	var supportedCiphers []uint16
	group := errgroup.Group{}
	for _, c := range realDefaultCipherSuitesTLS13 {
		c := c
		group.Go(func() error {
			// Override the internal slice!
			varDefaultCipherSuitesTLS13 = []uint16{c}

			conn, err := net.Dial("tcp", hostname+":443")
			if err != nil {
				return err
			}

			client := tls.Client(conn, &tls.Config{
				ServerName: hostname,
				MinVersion: tls.VersionTLS13,
				MaxVersion: tls.VersionTLS13,
			})
			_ = client.Handshake()
			_ = client.Close()

			if client.ConnectionState().CipherSuite == c {
				supportedCiphersLock.Lock()
				supportedCiphers = append(supportedCiphers, c)
				supportedCiphersLock.Unlock()
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	// Reset the internal slice back to the full set
	varDefaultCipherSuitesTLS13 = realDefaultCipherSuitesTLS13

	return supportedCiphers, nil
}

func SupportedTLS12Ciphers(hostname string) ([]uint16, error) {
	// Taken from https://golang.org/pkg/crypto/tls/#pkg-constants
	var allCiphers = []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	}

	supportedCiphersLock := sync.Mutex{}
	var supportedCiphers []uint16

	group := errgroup.Group{}
	for _, c := range allCiphers {
		c := c
		group.Go(func() error {
			conn, err := net.Dial("tcp", hostname+":443")
			if err != nil {
				return err
			}

			client := tls.Client(conn, &tls.Config{
				ServerName:   hostname,
				CipherSuites: []uint16{c},
				MinVersion:   tls.VersionTLS12,
				MaxVersion:   tls.VersionTLS12,
			})
			_ = client.Handshake()
			_ = client.Close()

			if client.ConnectionState().CipherSuite == c {
				supportedCiphersLock.Lock()
				supportedCiphers = append(supportedCiphers, c)
				supportedCiphersLock.Unlock()
			}
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return supportedCiphers, nil
}
