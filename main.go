package main

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/findy-network/findy-agent-api/grpc/ops"
	"github.com/findy-network/findy-grpc/jwt"
	"github.com/findy-network/findy-grpc/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"google.golang.org/grpc"
)

var tls = flag.Bool("tls", true, "use TLS communication")

func main() {
	flag.Parse()

	// whe want this for glog, this is just a tester, not a real world service
	err2.Check(flag.Set("logtostderr", "true"))

	pki := rpc.LoadPKI("./cert")
	glog.V(1).Infof("starting gRPC server with\ncrt:\t%s\nkey:\t%s\nclient:\t%s",
		pki.Server.CertFile, pki.Server.KeyFile, pki.Client.CertFile)
	rpc.Serve(&rpc.ServerCfg{
		Port: 50051,
		PKI:  pki,
		Register: func(s *grpc.Server) error {
			ops.RegisterDevOpsServer(s, &devOpsServer{Root: "findy-root"})
			glog.V(10).Infoln("GRPC registration all done")
			return nil
		},
	})
}

type devOpsServer struct {
	ops.UnimplementedDevOpsServer
	Root string
}

func (d devOpsServer) Enter(ctx context.Context, cmd *ops.Cmd) (cr *ops.CmdReturn, err error) {
	defer err2.Return(&err)

	user := jwt.User(ctx)

	if user != d.Root {
		return &ops.CmdReturn{Type: cmd.Type}, errors.New("access right")
	}

	glog.V(3).Infoln("dev ops cmd", cmd.Type)
	cmdReturn := &ops.CmdReturn{Type: cmd.Type}

	switch cmd.Type {
	case ops.Cmd_PING:
		response := fmt.Sprintf("%s, ping ok", "TEST")
		cmdReturn.Response = &ops.CmdReturn_Ping{Ping: response}
	case ops.Cmd_LOGGING:
		//agencyCmd.ParseLoggingArgs(cmd.GetLogging())
		//response = fmt.Sprintf("logging = %s", cmd.GetLogging())
	case ops.Cmd_COUNT:
		response := fmt.Sprintf("%d/%d cloud agents",
			100, 1000)
		cmdReturn.Response = &ops.CmdReturn_Ping{Ping: response}
	}
	return cmdReturn, nil
}
