package main

import (
	"flag"

	rpcserver "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcserver"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	cert = flag.String("cert", "../../../scripts/e2e/cert/", "TLS cert path")
	port = flag.Int("port", 50053, "agency host gRPC port")
)

func main() {
	flag.Parse()

	// we want this for glog, this is just a tester, not a real world service
	try.To(flag.Set("logtostderr", "true"))
	assert.SetDefault(assert.Production)

	rpcserver.Serve(*cert, *port)
}
