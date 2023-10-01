package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	pb "grpc_sign/sign_service"
)

var privateKeyPath string

type server struct {
	pb.UnimplementedSignServiceServer
	privateKey *ecdsa.PrivateKey
}

func (s *server) SignMessage(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	if s.privateKey == nil {
		return nil, status.Errorf(codes.Internal, "Private key is not loaded")
	}

	// Sign the message
	signature, err := ecdsa.SignASN1(rand.Reader, s.privateKey, req.GetHash())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to sign message: %v", err)
	}

	// Serialize the signature
	signatureBytes := signature

	return &pb.SignResponse{Signature: signatureBytes}, nil
}

func loadPrivateKey() (*ecdsa.PrivateKey, error) {
	// Load the private key from the PEM file
	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM file")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func main() {
	flag.StringVar(&privateKeyPath, "privateKey", "../../private_key.pem", "Path to the PEM file of the private key")
	flag.Parse()

	if privateKeyPath == "" {
		log.Fatal("Please provide a path to the PEM file of the private key using the -privateKey flag")
	}

	privateKey, err := loadPrivateKey()
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	listen, err := net.Listen("tcp", ":50051") // Replace with your desired port
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	// Generate a self-signed certificate
	cert, err := generateSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	creds := credentials.NewServerTLSFromCert(&cert)

	s := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterSignServiceServer(s, &server{privateKey: privateKey})

	fmt.Println("gRPC server is running on port 50051") // Update with your desired port

	if err := s.Serve(listen); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Your Organization"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
