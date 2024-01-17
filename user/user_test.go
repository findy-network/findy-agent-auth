package user_test

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-auth/user"
	ops "github.com/findy-network/findy-common-go/grpc/ops/v1"
	"github.com/findy-network/findy-common-go/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

var (
	dialOpts       = []grpc.DialOption{grpc.WithContextDialer(dialer())}
	insecureServer *grpc.Server
	aServer        = &agencyServer{}
)

type agencyServer struct {
	ops.UnimplementedAgencyServiceServer
}

func (d agencyServer) PSMHook(*ops.DataHook, ops.AgencyService_PSMHookServer) error {
	return status.Errorf(codes.Unimplemented, "method PSMHook not implemented")
}

func (d agencyServer) Onboard(context.Context, *ops.Onboarding) (*ops.OnboardResult, error) {
	return &ops.OnboardResult{
		Ok: true,
		Result: &ops.OnboardResult_OKResult{
			CADID: "CADID",
		},
	}, nil
}

func dialer() func(context.Context, string) (net.Conn, error) {
	const bufSize = 1024 * 1024

	listener := bufconn.Listen(bufSize)

	s, lis, err := rpc.PrepareServe(&rpc.ServerCfg{
		Port:    50052,
		TestLis: listener,
		Register: func(s *grpc.Server) error {
			ops.RegisterAgencyServiceServer(s, aServer)
			glog.V(10).Infoln("GRPC registration all done")
			return nil
		},
	})
	if err != nil {
		panic(fmt.Errorf("unable to register mock server %v", err))
	}

	insecureServer = s

	go func() {
		defer err2.Catch()

		try.To(s.Serve(lis))
	}()

	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}

func TestMain(m *testing.M) {
	try.To(flag.Set("logtostderr", "true"))
	try.To(flag.Set("v", "0"))
	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func setUp() {
	user.InitWithOpts("", "localhost", 50052, true, dialOpts)
}

func tearDown() {
	insecureServer.GracefulStop()
}

func TestOnboardInsecure(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	u := user.New("username", "displayName", "seed")

	try.To(u.AllocateCloudAgent("findy-root", 3*time.Second))
}
