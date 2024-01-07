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

		sendPL := try.To1(json.Marshal(userCfg))
		req := httptest.NewRequest(http.MethodPost, urlBeginRegister,
			bytes.NewReader(sendPL))
		w := httptest.NewRecorder()

		BeginRegistration(w, req)

		res := w.Result()
		defer res.Body.Close()
		data := try.To1(io.ReadAll(res.Body))
		//want := `{"rp":{"name":"Findy Agency","id":"http://localhost"},"user":{"name":"test-user","displayName":"test-user","id":"wbXI2OaJrKaAAQ"},"challenge":"qCzrcuGEVcSeXiT75HhdTiOfjwWGwa5iCkj1ibq5fDk","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"}}`
		assert.Equal(res.StatusCode, http.StatusOK)
		assert.That(len(data) > 0)
		s := string(data)
		println(s)

		s = fmt.Sprintf(`{"publicKey": %s}`, s)
		//assert.Equal(string(data), want)

		// TODO: continue with client logic!
		acator.Origin = *try.To1(url.Parse(defaultOrigin))
		repl := try.To1(acator.Register(bytes.NewBufferString(s)))
		//repl := try.To1(acator.Register(res.Body))

		//data = try.To1(io.ReadAll(repl))
		//assert.That(len(data) > 0)

		// TODO: second http POST request NOTE: this is must that next work
		// because this adds the user to enclave. 
		request := httptest.NewRequest(http.MethodPost, urlFinishRegister, repl)
		// Copy the Cookie over to a new Request
		request.Header = http.Header{"Cookie": w.HeaderMap["Set-Cookie"]}
		w = httptest.NewRecorder()

		FinishRegistration(w, request)
		res2 := w.Result()
		defer res2.Body.Close()
		data = try.To1(io.ReadAll(res2.Body))
		assert.Equal(res2.StatusCode, http.StatusOK)
		assert.That(len(data) > 0)
		s = string(data)
		println(s)
	})
//	t.Run("login", func(t *testing.T) {
//		defer assert.PushTester(t)()
//
//		sendPL := try.To1(json.Marshal(userLoginCfg))
//		req := httptest.NewRequest(http.MethodGet, urlBeginLogin,
//			bytes.NewReader(sendPL))
//		w := httptest.NewRecorder()
//
//		BeginLogin(w, req)
//
//		res := w.Result()
//		defer res.Body.Close()
//		data := try.To1(io.ReadAll(res.Body))
//		//want := `{"rp":{"name":"Findy Agency","id":"http://localhost"},"user":{"name":"test-user","displayName":"test-user","id":"wbXI2OaJrKaAAQ"},"challenge":"qCzrcuGEVcSeXiT75HhdTiOfjwWGwa5iCkj1ibq5fDk","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"}}`
//		assert.Equal(res.StatusCode, http.StatusOK, string(data))
//		assert.That(len(data) > 0)
//		s := string(data)
//		println(s)
//
//		s = fmt.Sprintf(`{"publicKey": %s}`, s)
//		//assert.Equal(string(data), want)
//
//		// TODO: continue with client logic!
//		acator.Origin = *try.To1(url.Parse("http://localhost"))
//		repl := try.To1(acator.Login(bytes.NewBufferString(s)))
//		//repl := try.To1(acator.Register(res.Body))
//
//		data = try.To1(io.ReadAll(repl))
//		assert.That(len(data) > 0)
//
//		// TODO: second http POST request
//	})
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
	//sessionStore = try.To1(session.NewStore())
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

