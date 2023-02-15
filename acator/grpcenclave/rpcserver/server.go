package rpcserver

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/findy-network/findy-agent-auth/acator/authn"
	"github.com/findy-network/findy-agent-auth/acator/grpcenclave"
	pb "github.com/findy-network/findy-common-go/grpc/authn/v1"
	"github.com/findy-network/findy-common-go/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
)

func Serve(certPath string, port int) {
	pki := rpc.LoadPKI(certPath)
	glog.V(3).Infof("starting gRPC server with\ncrt:\t%s\nkey:\t%s\nclient:\t%s",
		pki.Server.CertFile, pki.Server.KeyFile, pki.Client.CertFile)
	rpc.Serve(&rpc.ServerCfg{
		Port: port,
		PKI:  pki,
		Register: func(s *grpc.Server) error {
			pb.RegisterAuthnServiceServer(s, &authnServer{})
			glog.V(10).Infoln("GRPC registration all done")
			return nil
		},
	})
}

type authnServer struct {
	pb.UnimplementedAuthnServiceServer
	atomic.Int64

	authnCmd *authn.Cmd
}

func (a *authnServer) Enter(
	cmd *pb.Cmd,
	server pb.AuthnService_EnterServer,
) (
	err error,
) {
	defer err2.Handle(&err, func() {
		glog.Errorf("---- grpc run error: %v", err)
		status := &pb.CmdStatus{
			Info: &pb.CmdStatus_Err{Err: "error"},
			Type: pb.CmdStatus_READY_ERR,
		}
		if err := server.Send(status); err != nil {
			glog.Errorln("error sending response:", err)
		}
	})

	// NOTE. Authentication is done by mutual TLS or must be done for this
	// service!

	glog.V(3).Infoln("=== authn Enter cmd:", cmd.Type)
	cmdID := a.Add(1)

	a.authnCmd = &authn.Cmd{
		SubCmd:        strings.ToLower(cmd.GetType().String()),
		UserName:      cmd.GetUserName(),
		PublicDIDSeed: cmd.GetPublicDIDSeed(),
		Url:           cmd.GetURL(),
		AAGUID:        cmd.GetAAGUID(),
		Counter:       cmd.GetCounter(),
		Token:         cmd.GetJWT(),
	}
	secEnc := &grpcenclave.Enclave{
		Cmd:     cmd,
		CmdID:   cmdID,
		OutChan: make(chan *pb.CmdStatus),
		InChan:  make(chan *pb.SecretMsg),
	}
	a.authnCmd.SecEnclave = secEnc

	go func() {
		defer err2.Catch(func(err error) {
			errStr := fmt.Sprintf("error: grpc server main: %v", err)
			glog.Error(errStr)
			status := &pb.CmdStatus{
				CmdID: cmdID,
				Info:  &pb.CmdStatus_Err{Err: errStr},
				Type:  pb.CmdStatus_READY_ERR,
			}
			if err := server.Send(status); err != nil {
				glog.Error("error sending response")
			}
			close(secEnc.OutChan)
		})
		r := try.To1(a.authnCmd.Exec(nil))
		secEnc.OutChan <- &pb.CmdStatus{
			CmdID:   cmdID,
			Type:    pb.CmdStatus_READY_OK,
			CmdType: cmd.GetType(),
			Info:    &pb.CmdStatus_Ok{
				Ok: &pb.CmdStatus_OKResult{
					JWT: r.Token,
				},
			},
		}
		close(secEnc.OutChan)
	}()

	for status := range secEnc.OutChan {
		glog.V(1).Infoln("<== status:", status.CmdType, status.CmdID)
		try.To(server.Send(status))
	}
	glog.V(1).Info("end Enter")
	return nil
}

func (a *authnServer) EnterSecret(
	ctx context.Context,
	smsg *pb.SecretMsg,
) (
	r *pb.SecretResult,
	err error,
) {
	r = &pb.SecretResult{Ok: false}

	defer err2.Handle(&err, func() {
		glog.Errorln("ERROR:", err)
		r.Result = err.Error()
	})

	glog.V(1).Infoln("secret:", smsg.GetType(), smsg.GetCmdID())
	secEnc, ok := a.authnCmd.SecEnclave.(*grpcenclave.Enclave)
	assert.That(ok)
	assert.NotNil(secEnc)
	assert.CNotNil(secEnc.InChan)

	secEnc.InChan <- smsg

	return
}
