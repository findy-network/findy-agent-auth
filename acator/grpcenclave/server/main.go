package main

import (
	"flag"

	rpcserver "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcserver"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	// TODO: for Dart we start playing without tls or other security
	// TODO: we need to build gzip packging to these golang stacks
	//cert = flag.String("cert", "../../../scripts/test-cert/", "TLS cert path")
	port = flag.Int("port", 50053, "agency host gRPC port")
)

func main() {
	flag.Parse()

	// we want this for glog, this is just a tester, not a real world service
	try.To(flag.Set("logtostderr", "true"))
	assert.SetDefault(assert.Production)

	rpcserver.Serve(*port)
}
