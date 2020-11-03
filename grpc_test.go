package findy_grpc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-api/grpc/ops"
	"github.com/findy-network/findy-grpc/jwt"
	"github.com/findy-network/findy-grpc/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024
const pingReturn = "This is a TEST"

var (
	lis     = bufconn.Listen(bufSize)
	server  *grpc.Server
	conn    *grpc.ClientConn
	doPanic = false
)

func TestMain(m *testing.M) {
	err2.Check(flag.Set("logtostderr", "true"))
	err2.Check(flag.Set("v", "0"))
	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func setUp() {
	runServer()
	var err error
	conn, err = newClient("findy-root", "localhost:50051")
	err2.Check(err) // just dump error info out, we are inside a test
}

func tearDown() {
	err := conn.Close()
	err2.Check(err) // just dump information out, we are inside a test
	server.GracefulStop()
}

func TestEnter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	c := ops.NewDevOpsClient(conn)
	r, err := c.Enter(ctx, &ops.Cmd{
		Type: ops.Cmd_PING,
	})
	assert.NoError(t, err)
	assert.Equal(t, pingReturn, r.GetPing())

	doPanic = true
	r, err = c.Enter(ctx, &ops.Cmd{
		Type: ops.Cmd_PING,
	})
	assert.Error(t, err)

	defer cancel()
}

func newClient(user, addr string) (conn *grpc.ClientConn, err error) {
	defer err2.Return(&err)

	pki := rpc.LoadPKI()

	glog.V(5).Infoln("client with user:", user)
	conn, err = rpc.ClientConn(rpc.ClientCfg{
		PKI:  *pki,
		JWT:  jwt.BuildJWT(user),
		Addr: addr,
		TLS:  true,
		Opts: []grpc.DialOption{grpc.WithContextDialer(bufDialer)},
	})
	err2.Check(err)
	return
}

func runServer() {
	pki := rpc.LoadPKI()
	glog.V(1).Infof("starting gRPC server with\ncrt:\t%s\nkey:\t%s\nclient:\t%s",
		pki.Server.CertFile, pki.Server.KeyFile, pki.Client.CertFile)

	go func() {
		defer err2.Catch(func(err error) {
			log.Fatal(err)
		})
		s, lis, err := rpc.PrepareServe(rpc.ServerCfg{
			Port:    50051,
			TLS:     true,
			PKI:     *pki,
			TestLis: lis,
			Register: func(s *grpc.Server) error {
				ops.RegisterDevOpsServer(s, &devOpsServer{Root: "findy-root"})
				glog.V(10).Infoln("GRPC registration all done")
				return nil
			},
		})
		err2.Check(err)
		server = s
		err2.Check(s.Serve(lis))
	}()
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

type devOpsServer struct {
	ops.UnimplementedDevOpsServer
	Root string
}

func (d devOpsServer) Enter(ctx context.Context, cmd *ops.Cmd) (cr *ops.CmdReturn, err error) {
	defer err2.Return(&err)

	if doPanic {
		panic("testing panic")
	}

	user := jwt.User(ctx)

	if user != d.Root {
		return &ops.CmdReturn{Type: cmd.Type}, errors.New("access right")
	}

	glog.V(3).Infoln("dev ops cmd", cmd.Type)
	cmdReturn := &ops.CmdReturn{Type: cmd.Type}

	switch cmd.Type {
	case ops.Cmd_PING:
		response := pingReturn
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
