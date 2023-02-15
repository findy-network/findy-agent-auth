package main

import (
	"flag"

	rpcserver "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcserver"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	cert = flag.String("cert", "../../../scripts/e2e/config/cert/", "TLS cert path")
	port = flag.Int("port", 50053, "agency host gRPC port")
)

func main() {
	flag.Parse()

	// whe want this for glog, this is just a tester, not a real world service
	try.To(flag.Set("logtostderr", "true"))
	assert.DefaultAsserter = assert.AsserterToError

	rpcserver.Serve(*cert, *port)
}
