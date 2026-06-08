package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "用法: %s host:port\n", os.Args[0])
		os.Exit(1)
	}
	addr := os.Args[1]

	fmt.Printf("正在连接 %s ...\n", addr)

	// 先尝试 QUIC (UDP)
	fmt.Printf("尝试 QUIC (UDP)...\n")
	certs, connType, err := tryQUIC(addr)
	if err != nil {
		fmt.Printf("QUIC 失败: %v\n", err)
		// fallback 到 TCP TLS
		fmt.Printf("尝试 TCP TLS...\n")
		certs, connType, err = tryTCPTLS(addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TCP TLS 也失败: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("\n✓ 连接成功 [%s]\n", connType)

	if len(certs) == 0 {
		fmt.Fprintln(os.Stderr, "未收到证书")
		os.Exit(1)
	}

	leaf := certs[0]
	fmt.Printf("\n── 叶证书（leaf）──\n")
	fmt.Printf("  Subject : %s\n", leaf.Subject.CommonName)
	fmt.Printf("  Issuer  : %s\n", leaf.Issuer.CommonName)
	fmt.Printf("  有效期  : %s → %s\n",
		leaf.NotBefore.Format("2006-01-02"),
		leaf.NotAfter.Format("2006-01-02"),
	)

	certDER := leaf.Raw
	hash := sha256.Sum256(certDER)
	pinHex := fmt.Sprintf("%x", hash)
	pinB64 := base64.StdEncoding.EncodeToString(hash[:])

	fmt.Printf("  pinSHA256 (hex)   : %s\n", pinHex)
	fmt.Printf("  pinSHA256 (base64): %s\n", pinB64)
}

// tryQUIC 尝试 QUIC 连接获取证书
func tryQUIC(addr string) ([]*x509.Certificate, string, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{})
	if err != nil {
		return nil, "", fmt.Errorf("QUIC 连接失败: %v", err)
	}
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState().TLS
	return state.PeerCertificates, "QUIC/UDP", nil
}

// tryTCPTLS 尝试 TCP TLS 连接获取证书
func tryTCPTLS(addr string) ([]*x509.Certificate, string, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConf)
	if err != nil {
		return nil, "", fmt.Errorf("TCP TLS 连接失败: %v", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	return state.PeerCertificates, "TCP/TLS", nil
}
