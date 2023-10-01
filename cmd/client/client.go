package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "grpc_sign/sign_service"
)

var (
	serverAddress string
	// message       string
	publicKeyPath string
	count         int
	threads       int
)

func init() {
	flag.StringVar(&serverAddress, "serverAddress", "localhost:50051", "Address of the gRPC server")
	// flag.StringVar(&message, "message", "", "Message to sign")
	flag.StringVar(&publicKeyPath, "publicKey", "", "Path to the PEM file of the public key")
	flag.IntVar(&count, "N", 1, "Number of requests")
	flag.IntVar(&threads, "threads", 1, "Number of concurrent requests")
	flag.Parse()
}

func main() {
	if /* message == "" ||*/ publicKeyPath == "" {
		log.Fatal("Usage: client -message <message> -publicKey <public_key.pem>")
	}

	// Load the public key from the PEM file
	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		log.Fatalf("Failed to load public key: %v", err)
	}

	conn, err := grpc.Dial(serverAddress, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})))
	if err != nil {
		log.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	client := pb.NewSignServiceClient(conn)

	ctx := context.Background()

	// hashed := sha256.Sum256([]byte(message))

	chout := make(chan time.Duration)
	chin := make(chan struct{})

	var once sync.Once

	hash := make([]byte, 32)
	rand.Read(hash)

	for i := 0; i < threads; i++ {
		// i := int64(i)
		go func() {
			for range chin {
				// sha256.Sum256(binary.AppendVarint([]byte{}, i))
				// Send the message to the server for signing
				start := time.Now()
				response, err := client.SignMessage(ctx, &pb.SignRequest{Hash: hash})
				latency := time.Since(start)
				if err != nil {
					log.Fatalf("Failed to call SignMessage: %v", err)
				}
				// fmt.Println("Signature:", response.Signature)
				// fmt.Println("Message signed and verified successfully!")
				once.Do(func() {
					// Verify the signature using the public key
					if !ecdsa.VerifyASN1(publicKey, hash, response.Signature) {
						log.Fatal("Signature verification failed")
					}
					// fmt.Println("Signature:", response.Signature)
					// fmt.Println("Message signed and verified successfully!")
				})
				chout <- latency
			}
		}()
	}
	start := time.Now()
	go func() {
		for i := 0; i < count; i++ {
			chin <- struct{}{}
		}
	}()
	var latency time.Duration
	for i := 0; i < count; i++ {
		latency += <-chout
	}
	delta := time.Since(start)
	pace := int(float64(count) / delta.Seconds())
	fmt.Printf("Made %d sign request in %v, %d signs/s, latency %v\n", count, delta, pace, latency/time.Duration(count))
}

func loadPublicKey(publicKeyPath string) (*ecdsa.PublicKey, error) {
	// Load the public key from the PEM file
	keyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM file")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPubKey, nil
}
