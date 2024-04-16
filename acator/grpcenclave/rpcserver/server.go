package rpcserver

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/findy-network/findy-agent-auth/acator/authn"
	"github.com/findy-network/findy-agent-auth/acator/grpcenclave"
	pb "github.com/findy-network/findy-common-go/grpc/authn/v1"
	"github.com/findy-network/findy-common-go/jwt"
	"github.com/findy-network/findy-common-go/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
)

func RegisterAuthnServer(s *grpc.Server) error {
	authnServ := &authnServer{}
	pb.RegisterAuthnServiceServer(s, authnServ)
	glog.V(0).Infoln("GRPC registration for authnServer")
	return nil
}

func Serve(port int) {
	rpc.Serve(&rpc.ServerCfg{
		NoAuthorization: true,

		Port:     port,
		Register: RegisterAuthnServer,
	})
}

type authnServer struct {
	pb.UnimplementedAuthnServiceServer

	root string

	id uint8
	mu sync.Mutex

	authnCmd [math.MaxUint8+1]*authn.Cmd
}

func (a *authnServer) AuthFuncOverride(
	ctx context.Context,
	fullMethodName string,
) (
	context.Context,
	error,
) {
	glog.V(1).Infoln("======== AuthFuncOverride", fullMethodName)
	// let's set some user name for future use, etc.
	return jwt.NewContextWithUser(ctx, a.root), nil
}

func (a *authnServer) Enter(
	cmd *pb.Cmd,
	server pb.AuthnService_EnterServer,
) (
	err error,
) {
	defer err2.Handle(&err, func(err error) error {
		glog.Errorf("---- grpc run error: %v", err)
		status := &pb.CmdStatus{
			Info: &pb.CmdStatus_Err{Err: "error"},
			Type: pb.CmdStatus_READY_ERR,
		}
		try.Out(server.Send(status)).Logf("error sending response:")
		return err
	})

	// NOTE. Authentication is done by mutual TLS or must be done for this
	// service!

	var (
		secEnc *grpcenclave.Enclave
		cmdID  uint8
	)
	a.tx(func() {
		cmdID = a.id
		a.id++
		glog.V(3).Infof("=== authn Enter cmd:%v, cmdID: %v", cmd.Type, cmdID)

		secEnc = &grpcenclave.Enclave{
			Cmd:     cmd,
			CmdID:   int64(cmdID),
			OutChan: make(chan *pb.CmdStatus),
			InChan:  make(chan *pb.SecretMsg),
		}
		a.authnCmd[cmdID] = &authn.Cmd{
			SubCmd:        strings.ToLower(cmd.GetType().String()),
			UserName:      cmd.GetUserName(),
			PublicDIDSeed: cmd.GetPublicDIDSeed(),
			URL:           cmd.GetURL(),
			AAGUID:        cmd.GetAAGUID(),
			Counter:       cmd.GetCounter(),
			Token:         cmd.GetJWT(),
			Origin:        cmd.GetOrigin(),
			SecEnclave:    secEnc,
		}
	})

	go func() {
		defer err2.Catch(err2.Err(func(err error) {
			errStr := fmt.Sprintf("error: grpc server main: %v", err)
			glog.Error(errStr)
			status := &pb.CmdStatus{
				CmdID: int64(cmdID),
				Info:  &pb.CmdStatus_Err{Err: errStr},
				Type:  pb.CmdStatus_READY_ERR,
			}
			try.Out(server.Send(status)).Logf("error sending response")
			// NOTE: we don't close channel here, context handles them
		}))

		var (
			r    authn.Result
			aCmd *authn.Cmd
		)
		a.tx(func() {
			aCmd = a.authnCmd[cmdID]
		})
		r = try.To1(aCmd.Exec(nil))

		secEnc.OutChan <- &pb.CmdStatus{
			CmdID:   int64(cmdID),
			Type:    pb.CmdStatus_READY_OK,
			CmdType: cmd.GetType(),
			Info: &pb.CmdStatus_Ok{
				Ok: &pb.CmdStatus_OKResult{
					JWT: r.Token,
				},
			},
		}
		//close(secEnc.OutChan)
	}()

loop:
	for {
		select {
		case <-server.Context().Done():
			break loop

		case status, ok := <-secEnc.OutChan:
			if !ok || status.GetType() == pb.CmdStatus_READY_OK {
				glog.V(1).Infoln("channel closed")
				break loop
			}
			glog.V(3).Infoln("<== status:", status.CmdType, status.CmdID)
			try.To(server.Send(status))
			continue loop
		}
	}
	return nil
}

func (a *authnServer) EnterSecret(
	_ context.Context,
	smsg *pb.SecretMsg,
) (
	r *pb.SecretResult,
	err error,
) {
	r = &pb.SecretResult{Ok: false}

	defer err2.Handle(&err, func(err error) error {
		glog.Errorln("ERROR:", err)
		r.Result = err.Error()
		return err
	})

	assert.NotNil(smsg)
	assert.NotEqual(smsg.GetCmdID(), math.MaxUint8+1)

	glog.V(3).Infof("secret type: %v, ID: %v", smsg.GetType(), smsg.GetCmdID())
	secEnc, ok := a.authnCmd[smsg.GetCmdID()].SecEnclave.(*grpcenclave.Enclave)
	assert.That(ok)
	assert.NotNil(secEnc)
	assert.CNotNil(secEnc.InChan)

	secEnc.InChan <- smsg

	return
}

func (a *authnServer) tx(fn func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn()
}
