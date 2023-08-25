package rpcclient

import (
	"context"
	"time"

	authn "github.com/findy-network/findy-common-go/grpc/authn/v1"
	"github.com/findy-network/findy-common-go/jwt"
	"github.com/findy-network/findy-common-go/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
)

func New(certPath, user, addr string) (conn *grpc.ClientConn, err error) {
	defer err2.Handle(&err)

	pki := rpc.LoadPKIWithServerName(certPath, addr)
	glog.V(5).Infoln("rpcclient with user:", user)
	conn = try.To1(rpc.ClientConn(rpc.ClientCfg{
		PKI:  pki,
		JWT:  jwt.BuildJWT(user),
		Addr: addr,
	}))
	return
}

func DoEnter(
	conn *grpc.ClientConn,
	ctx context.Context,
	cmd *authn.Cmd,
) (
	ch chan *authn.CmdStatus,
	err error,
) {
	defer err2.Handle(&err)

	c := authn.NewAuthnServiceClient(conn)
	statusCh := make(chan *authn.CmdStatus)

	stream := try.To1(c.Enter(ctx, cmd))
	glog.V(3).Infoln("successful start of:", cmd.GetType())
	go func() {
		defer err2.Catch(err2.Err(func(err error) {
			glog.V(3).Infoln("err when reading response", err)
			close(statusCh)
		}))
		for {
			status, err := stream.Recv()
			if try.IsEOF(err) {
				glog.V(3).Infoln("status stream end")
				close(statusCh)
				break
			}
			glog.V(4).Infoln("--> cmd status:",
				status.GetCmdID(),
				status.GetSecType(),
			)
			statusCh <- status
		}
	}()
	return statusCh, nil
}

func DoEnterSecret(
	conn *grpc.ClientConn,
	smsg *authn.SecretMsg,
) (
	res *authn.SecretResult,
	err error,
) {
	defer err2.Handle(&err)

	c := authn.NewAuthnServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	glog.V(3).Infoln("going to send SecretMsg:", smsg.Type)
	res = try.To1(c.EnterSecret(ctx, smsg))

	glog.V(3).Infoln("successful sent of SecretMsg:", smsg.Type)
	return res, nil
}
