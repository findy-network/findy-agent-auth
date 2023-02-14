package main

import (
	"flag"

	rpcserver "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcserver"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	port = flag.Int("port", 50051, "agency host gRPC port")
)

func main() {
	flag.Parse()

	// whe want this for glog, this is just a tester, not a real world service
	try.To(flag.Set("logtostderr", "true"))
	assert.DefaultAsserter = assert.AsserterToError

	rpcserver.Serve(*port)
}
