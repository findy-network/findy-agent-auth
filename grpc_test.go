package findy_grpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-api/grpc/agency"
	"github.com/findy-network/findy-grpc/jwt"
	"github.com/findy-network/findy-grpc/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var (
	lis = bufconn.Listen(bufSize)
	tls = true
)

func TestEnter(t *testing.T) {
	RunServer()

	conn, err := newClient("findy-root", "localhost:50051")
	assert.NoError(t, err)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	c := agency.NewDevOpsClient(conn)
	r, err := c.Enter(ctx, &agency.Cmd{
		Type: agency.Cmd_PING,
	})
	assert.NoError(t, err)
	fmt.Println("result:", r.GetPing())
	defer cancel()
}

func newClient(user, addr string) (conn *grpc.ClientConn, err error) {
	defer err2.Return(&err)

	goPath := os.Getenv("GOPATH")
	tlsPath := path.Join(goPath, "src/github.com/findy-network/findy-grpc/cert")
	pw := rpc.PKI{
		Server: rpc.CertFiles{
			CertFile: path.Join(tlsPath, "server/server.crt"),
		},
		Client: rpc.CertFiles{
			CertFile: path.Join(tlsPath, "client/client.crt"),
			KeyFile:  path.Join(tlsPath, "client/client.key"),
		},
	}

	glog.V(5).Infoln("client with user:", user)
	conn, err = rpc.ClientConn(rpc.ClientCfg{
		PKI:  pw,
		JWT:  jwt.BuildJWT(user),
		Addr: addr,
		TLS:  tls,
		Opts: []grpc.DialOption{grpc.WithContextDialer(bufDialer)},
	})
	err2.Check(err)
	return
}

func RunServer() {
	goPath := os.Getenv("GOPATH")
	tlsPath := path.Join(goPath, "src/github.com/findy-network/findy-grpc/cert")
	certFile := path.Join(tlsPath, "server/server.crt")
	keyFile := path.Join(tlsPath, "server/server.key")
	clientCertFile := path.Join(tlsPath, "client/client.crt")

	glog.V(1).Infof("starting gRPC server with\ncrt:\t%s\nkey:\t%s\nclient:\t%s",
		certFile, keyFile, clientCertFile)

	go func() {
		rpc.Serve(rpc.ServerCfg{
			Port: 50051,
			TLS:  tls,
			PKI: rpc.PKI{
				Server: rpc.CertFiles{
					CertFile: certFile,
					KeyFile:  keyFile,
				},
				Client: rpc.CertFiles{
					CertFile: clientCertFile,
				},
			},
			TestLis: lis,
			Register: func(s *grpc.Server) error {
				agency.RegisterDevOpsServer(s, &devOpsServer{Root: "findy-root"})
				glog.V(10).Infoln("GRPC registration all done")
				return nil
			},
		})
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

type devOpsServer struct {
	agency.UnimplementedDevOpsServer
	Root string
}

func (d devOpsServer) Enter(ctx context.Context, cmd *agency.Cmd) (cr *agency.CmdReturn, err error) {
	defer err2.Return(&err)

	user := jwt.User(ctx)

	if user != d.Root {
		return &agency.CmdReturn{Type: cmd.Type}, errors.New("access right")
	}

	glog.V(3).Infoln("dev ops cmd", cmd.Type)
	cmdReturn := &agency.CmdReturn{Type: cmd.Type}

	switch cmd.Type {
	case agency.Cmd_PING:
		response := fmt.Sprintf("%s, ping ok", "This is a TEST")
		cmdReturn.Response = &agency.CmdReturn_Ping{Ping: response}
	case agency.Cmd_LOGGING:
		//agencyCmd.ParseLoggingArgs(cmd.GetLogging())
		//response = fmt.Sprintf("logging = %s", cmd.GetLogging())
	case agency.Cmd_COUNT:
		response := fmt.Sprintf("%d/%d cloud agents",
			100, 1000)
		cmdReturn.Response = &agency.CmdReturn_Ping{Ping: response}
	}
	return cmdReturn, nil
}
