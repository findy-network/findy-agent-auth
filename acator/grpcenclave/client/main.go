package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/findy-network/findy-agent-auth/acator/enclave"
	rpcclient "github.com/findy-network/findy-agent-auth/acator/grpcenclave/rpcclient"
	pb "github.com/findy-network/findy-common-go/grpc/authn/v1"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"
)

var (
	user       = flag.String("user", "findy-root", "test user name")
	serverAddr = flag.String("addr", "localhost", "agency host gRPC address")
	port       = flag.Int("port", 50051, "agency host gRPC port")

	khmap = make(map[int64]enclave.KeyHandle)
	keyID = atomic.Int64{}

	conn   *grpc.ClientConn
	ctx    context.Context
	cancel context.CancelFunc
)

func main() {
	err2.SetPanicTracer(os.Stderr)
	defer err2.Catch(func(err error) {
		glog.Error(err)
	})
	flag.Parse()

	// we want this for glog, this is just a tester, not a real world service
	try.To(flag.Set("logtostderr", "true"))

	conn = try.To1(rpcclient.New(*user, fmt.Sprintf("%s:%d", *serverAddr, *port)))
	defer conn.Close()

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	statusCh := try.To1(rpcclient.DoEnter(conn, ctx, &pb.Cmd{
		Type:          pb.Cmd_LOGIN,
		UserName:      "hepo2",
		PublicDIDSeed: "",
		URL:           "http://localhost:8090",
		AAGUID:        "12c85a48-4baf-47bd-b51f-f192871a1511",
		Counter:       0,
		JWT:           "",
		Origin:        "",
	}))

	//secEnc := enclave.Store
	secEnc := enclave.New("289239187d7c395044976416280b6a283bf65562a06b0bdc3a75a4db4adfe7c7")
	assert.INotNil(secEnc)

loop:
	for status := range statusCh {
		glog.Infoln("loop status:", status.GetType(), status.GetCmdID())

		switch status.GetType() {
		case pb.CmdStatus_STATUS:
			status.GetSecType()
			switch status.GetSecType() {
			case pb.SecretMsg_NEW_HANDLE:
				id := keyID.Add(1)
				khmap[id] = try.To1(secEnc.NewKeyHandle())
				smsg := &pb.SecretMsg{
					CmdID: status.CmdID,
					Type:  status.SecType,
					Info: &pb.SecretMsg_Handle_{
						Handle: &pb.SecretMsg_Handle{
							ID: id,
						},
					},
				}
				rpcclient.DoEnterSecret(conn, smsg)
			case pb.SecretMsg_IS_KEY_HANDLE:
				ok, kh := secEnc.IsKeyHandle(status.GetEnclave().CredID)
				var (
					id   int64
					smsg *pb.SecretMsg
				)
				if ok {
					for k, v := range khmap {
						if kh == v {
							id = k
							break
						}
					}
					if id <= 0 {
						id = keyID.Add(1)
						khmap[id] = kh
					}
					smsg = &pb.SecretMsg{
						CmdID: status.CmdID,
						Type:  status.SecType,
						Info: &pb.SecretMsg_Handle_{
							Handle: &pb.SecretMsg_Handle{
								ID: id,
							},
						},
					}
				} else {
					smsg = &pb.SecretMsg{
						CmdID: status.CmdID,
						Type:  pb.SecretMsg_ERROR,
						Info: &pb.SecretMsg_Err{
							Err: &pb.SecretMsg_Error{
								Info: "not key handle",
							},
						},
					}
				}
				rpcclient.DoEnterSecret(conn, smsg)
			case pb.SecretMsg_ID:
				tryProcess(status,
					func(kh enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error) {
						d = kh.ID()
						return
					})
			case pb.SecretMsg_CBOR_PUB_KEY:
				tryProcess(status,
					func(kh enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error) {
						defer err2.Handle(&err)
						d = try.To1(kh.CBORPublicKey())
						return
					})
			case pb.SecretMsg_SIGN:
				tryProcess(status,
					func(kh enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error) {
						defer err2.Handle(&err)
						s = try.To1(kh.Sign(data[0]))
						return
					})
			case pb.SecretMsg_VERIFY:
				tryProcess(status,
					func(kh enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error) {
						ok := kh.Verify(data[0], data[1])
						if !ok {
							err = fmt.Errorf("cannot verify singnature")
						}
						return
					})
			case pb.SecretMsg_ERROR:
				smsg := &pb.SecretMsg{
					CmdID: status.CmdID,
					Type:  pb.SecretMsg_ERROR,
					Info: &pb.SecretMsg_Err{
						Err: &pb.SecretMsg_Error{
							Info: "not key handle",
						},
					},
				}
				rpcclient.DoEnterSecret(conn, smsg)
			}

		case pb.CmdStatus_READY_OK:
			glog.V(3).Info("gRPC authn call OK")
			jwt := status.GetOk().GetJWT()
			fmt.Println(jwt)
			break loop

		case pb.CmdStatus_READY_ERR:
			glog.V(3).Infoln("gRPC authn call ERR:",
				status.GetErr(),
			)
			break loop
		}

	}
	glog.V(3).Infoln("main ends")

}

func tryProcess(
	status *pb.CmdStatus,
	caller func(handle enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error),
) {
	var (
		smsg *pb.SecretMsg
	)
	defer err2.Catch(func(err error) {
		smsg = &pb.SecretMsg{
			CmdID: status.CmdID,
			Type:  pb.SecretMsg_ERROR,
			Info: &pb.SecretMsg_Err{
				Err: &pb.SecretMsg_Error{
					Info: "not key handle",
				},
			},
		}
		rpcclient.DoEnterSecret(conn, smsg)
	})

	id := status.GetHandle().ID
	datas := make([][]byte, 0, 2)
	if status.GetHandle().Data != nil {
		datas = append(datas, status.GetHandle().Data)
	}
	if status.GetHandle().Sign != nil {
		datas = append(datas, status.GetHandle().Sign)
	}
	kh, ok := khmap[id]
	if ok {
		data, sig := try.To2(caller(kh, datas...))
		smsg = &pb.SecretMsg{
			CmdID: status.CmdID,
			Type:  status.SecType,
			Info: &pb.SecretMsg_Handle_{
				Handle: &pb.SecretMsg_Handle{
					ID:   id,
					Data: data,
					Sign: sig,
				},
			},
		}
	} else {
		err2.Throwf("key handle not found")
	}
	rpcclient.DoEnterSecret(conn, smsg)
}
