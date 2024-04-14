package rpcclient

import (
	"context"
	"time"

	"github.com/findy-network/findy-common-go/agency/client"
	authn "github.com/findy-network/findy-common-go/grpc/authn/v1"
	"github.com/findy-network/findy-common-go/rpc"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
)

func New(cert, addr string, port int) (conn *grpc.ClientConn, err error) {
	defer err2.Handle(&err)

	var cfg *rpc.ClientCfg
	if cert == "" {
		cfg = client.BuildInsecureClientConnBase(addr, port, nil)
	} else {
		cfg = client.BuildClientConnBase(cert, addr, port, nil)
	}
	return rpc.ClientConn(*cfg)
}

func DoEnter(
	conn *grpc.ClientConn,
	ctx context.Context, //nolint: revive
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
			glog.V(4).Infof("--> cmd ID:%v, status: %v, (secType: %v)",
				status.GetCmdID(),
				status.GetType(),
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
