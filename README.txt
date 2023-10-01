Generate gRPC code:

$ go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
$ go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
$ protoc --go_out=. --go-grpc_out=. sign_service.proto

Generate key pair:

$ openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
$ openssl ec -in private_key.pem -pubout -out public_key.pem

Compile client or server:

$ CGO_ENABLED=0 go build ./cmd/client
$ CGO_ENABLED=0 go build ./cmd/server
