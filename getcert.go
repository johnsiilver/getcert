/*
Package getcert allows the dialing of a TLS service (http or gRPC) without possessing the public key.
This is useful in situations where you don't need a preshared cert because traffic is under internal
control (internal Kubernetes routing) or when you have a non self signed cert that can be verified
against a chain of trust with a Certificate Authority (CA). The server already has the cert, why would
you want to have a static cert to manage?

For internal traffic (where DNS is under your control), you can do:

	tlsCert, xCerts, err := FromTLSServer("service.com:443", true)

For a non self signed certificate you verify with a CA:

	tlsCert, xCerts, err := FromTLSServer("service.com:443", false)

You can use this in an http.Client with:

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "service.com", Certificates: []tls.Certificate{tlsCert},
				InsecureSkipVerify: true, // Set only if you set skipVerify to true above
			},
		},
	}

	repsp, err := client.Get("service.com:443")

You can also use this as a gRPC DialOption:

	conn, err := grpc.Dial(*serverAddr, grpc.NewServerTLSFromCert(tlsCert))
	if err != nil {
	    ...
	}
	defer conn.Close()

Note: I don't know that I believe there is something completely under internal control that is safe.
I suggest always using verify and limiting this to only certain trusted CAs. But that's your call.

This library is useful where mutual authentication via certs is not needed and you do not want to use
self signed certs (which gRPC seems to encourage, but this is no better than preshared secrets and rarely
 rotate). If your require authentication and don't want client certs, use Oauth or some other mechanism.
*/
package getcert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// FromTLSServer does a TLS handshake with the TLS server at servicePort and retrieves the server's
// public certificate. If skipVerify is set, it will not attempt to validate the server's certificate
// chain. All certificates in the chain are returned in the tls.Certificate (which can hold multiple certs)
// and also as the x509.Certificate list.
func FromTLSServer(servicePort string, skipVerify bool) (tls.Certificate, []*x509.Certificate, error) {
	sp := strings.Split(servicePort, ":")
	if len(sp) != 2 {
		return tls.Certificate{}, nil, fmt.Errorf("servicePort must be the DNS hostname + ':' + port, was %s", servicePort)
	}

	if _, err := strconv.Atoi(sp[1]); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("servicePort must have integer after ':', had %s", sp[1])
	}

	nconn, err := net.Dial("tcp", servicePort)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("problem dialing %s: %s", servicePort, err)
	}

	config := &tls.Config{ServerName: sp[0], InsecureSkipVerify: skipVerify}
	tconn := tls.Client(nconn, config)
	if err := tconn.Handshake(); err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("problem with TLS Handshake: %s", err)
	}

	tlsCert := tls.Certificate{}
	for _, cert := range tconn.ConnectionState().PeerCertificates {
		tlsCert.Certificate = append(tlsCert.Certificate, cert.Raw)
	}
	return tlsCert, tconn.ConnectionState().PeerCertificates, nil
}
