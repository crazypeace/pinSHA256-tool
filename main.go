package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
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

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, tlsConf, &quic.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接失败: %v\n", err)
		os.Exit(1)
	}
	defer conn.CloseWithError(0, "")

	state := conn.ConnectionState().TLS
	certs := state.PeerCertificates
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
