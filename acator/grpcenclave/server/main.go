package main

import (
	"flag"
	"os"

	rpcserver "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcserver"
	"github.com/lainio/err2"
	_ "github.com/lainio/err2/assert"
)

var (
	// TODO: for Dart we start playing without tls or other security
	// TODO: we need to build gzip packging to these golang stacks
	//cert = flag.String("cert", "../../../scripts/test-cert/", "TLS cert path")
	port = flag.Int("port", 50053, "agency host gRPC port")
)

func main() {
	os.Args = append(os.Args,
		"-logtostderr",
	)
	err2.Catch()

	flag.Parse()

	rpcserver.Serve(*port)
}
