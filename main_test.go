package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/findy-network/findy-agent-auth/acator"
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
	userCfg = userInfo{
		Username:         "test-user",
		DisplayName:      "Test Number One",
		UserVerification: "",
		Seed:             "",
	}
	userLoginCfg = loginUserInfo{Username: "test-user"}
)

func TestRegisterBegin(t *testing.T) {
	t.Run("register", func(t *testing.T) {
		defer assert.PushTester(t)()

		ti := &testInfo{
			sendPL:    try.To1(json.Marshal(userCfg)),
			endpoints: []string{urlBeginRegister, urlFinishRegister},
			calls: []func(w http.ResponseWriter, r *http.Request){
				BeginRegistration, FinishRegistration,
			},
			buildCalls: []func(jsonStream io.Reader) (io.Reader, error){
				acator.Register,
			},
		}
		doTest(t, ti)
	})
	t.Run("login", func(t *testing.T) {
		defer assert.PushTester(t)()

		ti := &testInfo{
			sendPL:    try.To1(json.Marshal(userLoginCfg)),
			endpoints: []string{urlBeginLogin, urlFinishLogin},
			calls: []func(w http.ResponseWriter, r *http.Request){
				BeginLogin, FinishLogin,
			},
			buildCalls: []func(jsonStream io.Reader) (io.Reader, error){
				acator.Login,
			},
		}
		doTest(t, ti)
	})
}

type testInfo struct {
	sendPL     []byte
	endpoints  []string
	calls      []func(w http.ResponseWriter, r *http.Request)
	buildCalls []func(jsonStream io.Reader) (outStream io.Reader, err error)
}

func doTest(t *testing.T, ti *testInfo) {
	t.Helper()

	req1 := httptest.NewRequest(http.MethodPost, ti.endpoints[0],
		bytes.NewReader(ti.sendPL))
	w := httptest.NewRecorder()

	ti.calls[0](w, req1)

	res := w.Result()
	defer res.Body.Close()
	data := try.To1(io.ReadAll(res.Body))
	assert.Equal(res.StatusCode, http.StatusOK)
	assert.That(len(data) > 0)
	s := string(data)
	s = fmt.Sprintf(`{"publicKey": %s}`, s)

	repl := try.To1(ti.buildCalls[0](bytes.NewBufferString(s)))

	req2 := httptest.NewRequest(http.MethodPost, ti.endpoints[1], repl)
	req2.Header = http.Header{"Cookie": res.Header["Set-Cookie"]}
	w = httptest.NewRecorder()

	ti.calls[1](w, req2)

	res2 := w.Result()
	defer res2.Body.Close()
	data = try.To1(io.ReadAll(res2.Body))
	assert.Equal(res2.StatusCode, http.StatusOK)
	assert.That(len(data) > 0)
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
	enclaveFile = "MEMORY_enc.bolt"
	enclaveBackup = ""
	enclaveKey = ""

	rpOrigin = defaultOrigin
	acator.Origin = *try.To1(url.Parse(defaultOrigin))

	setupEnv()

	// overwrite with our mock gRPC endpoint and server
	user.InitWithOpts("", "localhost", 50052, true, dialOpts)
}

func tearDown() {}

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
		defer err2.Catch(err2.Err(func(err error) {
			log.Fatal(err)
		}))
		try.To(s.Serve(lis))
	}()

	return func(context.Context, string) (net.Conn, error) {
		return listener.Dial()
	}
}
