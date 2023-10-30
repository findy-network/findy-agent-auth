package main

import (
	"flag"
	"os"

	rpcserver "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcserver"
	"github.com/lainio/err2"
	_ "github.com/lainio/err2/assert"
)

var (
	cert = flag.String("cert", "../../../scripts/test-cert/", "TLS cert path")
	port = flag.Int("port", 50053, "agency host gRPC port")
)

func main() {
	os.Args = append(os.Args,
		"-logtostderr",
	)
	err2.Catch()

	flag.Parse()

	rpcserver.Serve(*cert, *port)
}
