package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
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
	// TODO: dart playground
	// cert       = flag.String("cert", "../../../scripts/test-cert/", "TLS cert path")

	cert       = flag.String("cert", "../../../../findy-agent/grpc/cert", "pki cert path")
	cmd        = flag.String("cmd", "login", "FIDO2 cmd: login/register")
	user       = flag.String("user", "elli", "test user name")
	serverAddr = flag.String("addr", "localhost", "agency host gRPC address")
	url        = flag.String("url", "http://localhost:8090", "FIDO2 server URL")
	origin     = flag.String("origin", "", "FIDO2 server needs origin if not in HTTPS")
	hexKey     = flag.String("key",
		"289239187d7c395044976416280b6a283bf65562a06b0bdc3a75a4db4adfe7c7",
		"soft cipher master key in HEX")

	port = flag.Int("port", 50053, "agency host gRPC port")

	khmap = make(map[int64]enclave.KeyHandle)
	keyID = atomic.Int64{}

	conn   *grpc.ClientConn
	ctx    context.Context
	cancel context.CancelFunc
)

// This is just for testing and development. The main problem to use automatic
// unit testing is that we need FIDO2 server running and our version needs
// agency running as well.

func main() {
	os.Args = append(os.Args,
		"-logtostderr",
	)
	defer err2.Catch()

	flag.Parse()
	glog.CopyStandardLogTo("ERROR")

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn = try.To1(rpcclient.New(*cert, *serverAddr, *port))
	defer conn.Close()

	glog.V(3).Infoln("Origin:", *origin)
	statusCh := try.To1(rpcclient.DoEnter(conn, ctx, &pb.Cmd{
		Type:          pb.Cmd_Type(pb.Cmd_Type_value[strings.ToUpper(*cmd)]),
		UserName:      *user,
		PublicDIDSeed: "",
		URL:           *url,
		AAGUID:        "12c85a48-4baf-47bd-b51f-f192871a1511",
		Counter:       0,
		JWT:           "",
		Origin:        *origin,
	}))

	secEnc := enclave.New(*hexKey)
	assert.INotNil(secEnc)

loop:
	for status := range statusCh {
		glog.V(1).Infoln("loop status:", status.GetType(), status.GetCmdID())

		switch status.GetType() {
		case pb.CmdStatus_STATUS:
			status.GetSecType()
			switch status.GetSecType() {
			case pb.SecretMsg_NEW_HANDLE:
				newKeyHandle(secEnc, status)
			case pb.SecretMsg_IS_KEY_HANDLE:
				isKeyHandle(secEnc, status)
			case pb.SecretMsg_ID:
				getID(status)
			case pb.SecretMsg_CBOR_PUB_KEY:
				getCBOR(status)
			case pb.SecretMsg_SIGN:
				sign(status)
			case pb.SecretMsg_VERIFY:
				verify(status)
			case pb.SecretMsg_ERROR:
				handleStatusErr(status)
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

func handleStatusErr(status *pb.CmdStatus) {
	smsg := newErrEnter(fmt.Errorf(status.GetErr()), "not key handle", status)
	try.To1(rpcclient.DoEnterSecret(conn, smsg))
}

func verify(status *pb.CmdStatus) {
	tryProcess(status,
		func(kh enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error) {
			ok := kh.Verify(data[0], data[1])
			if !ok {
				err = fmt.Errorf("cannot verify singnature")
			}
			return
		})
}

func sign(status *pb.CmdStatus) {
	tryProcess(status,
		func(kh enclave.KeyHandle, data ...[]byte) (d []byte, s []byte, err error) {
			defer err2.Handle(&err)
			s = try.To1(kh.Sign(data[0]))
			return
		})
}

func getCBOR(status *pb.CmdStatus) {
	tryProcess(status,
		func(kh enclave.KeyHandle, _ ...[]byte) (d []byte, s []byte, err error) {
			defer err2.Handle(&err)
			d = try.To1(kh.CBORPublicKey())
			return
		})
}

func getID(status *pb.CmdStatus) {
	tryProcess(status,
		func(kh enclave.KeyHandle, _ ...[]byte) (d []byte, s []byte, err error) {
			d = kh.ID()
			return
		})
}

func isKeyHandle(secEnc *enclave.Enclave, status *pb.CmdStatus) {
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
			Info: &pb.SecretMsg_Handle{
				Handle: &pb.SecretMsg_HandleMsg{
					ID: id,
				},
			},
		}
	} else {
		smsg = newErrEnter(fmt.Errorf("error"), "not key handle", status)
	}
	try.To1(rpcclient.DoEnterSecret(conn, smsg))
}

func newErrEnter(err error, msg string, status *pb.CmdStatus) *pb.SecretMsg {
	return &pb.SecretMsg{
		CmdID: status.CmdID,
		Type:  pb.SecretMsg_ERROR,
		Info: &pb.SecretMsg_Err{
			Err: &pb.SecretMsg_ErrorMsg{
				Info: fmt.Sprintf(msg+": %w", err),
			},
		},
	}
}

func newKeyHandle(secEnc *enclave.Enclave, status *pb.CmdStatus) {
	id := keyID.Add(1)
	var smsg *pb.SecretMsg
	kh := try.Out1(secEnc.NewKeyHandle()).
		Handle(func(err error) error {
			smsg = newErrEnter(err, "cannot create error handle", status)
			return nil
		}).Val1

	noErr := smsg == nil
	if noErr {
		khmap[id] = kh
		smsg = &pb.SecretMsg{
			CmdID: status.CmdID,
			Type:  status.SecType,
			Info: &pb.SecretMsg_Handle{
				Handle: &pb.SecretMsg_HandleMsg{
					ID: id,
				},
			},
		}
	}
	try.To1(rpcclient.DoEnterSecret(conn, smsg))
}

func tryProcess(
	status *pb.CmdStatus,
	caller func(
		handle enclave.KeyHandle,
		data ...[]byte,
	) (d []byte, s []byte, err error),
) {
	var (
		smsg *pb.SecretMsg
	)
	defer err2.Catch(err2.Err(func(err error) {
		smsg = newErrEnter(err, "error: processing", status)
		try.Out1(rpcclient.DoEnterSecret(conn, smsg)).Logf()
	}))

	extHandle := status.GetHandle()
	id := extHandle.ID
	datas := make([][]byte, 0, 2)
	if extHandle.Data != nil {
		datas = append(datas, extHandle.Data)
	}
	if extHandle.Sign != nil {
		datas = append(datas, extHandle.Sign)
	}
	kh, ok := khmap[id]
	if ok {
		data, sig := try.To2(caller(kh, datas...))
		smsg = &pb.SecretMsg{
			CmdID: status.CmdID,
			Type:  status.SecType,
			Info: &pb.SecretMsg_Handle{
				Handle: &pb.SecretMsg_HandleMsg{
					ID:   id,
					Data: data,
					Sign: sig,
				},
			},
		}
	} else {
		err2.Throwf("key handle not found")
	}
	try.To1(rpcclient.DoEnterSecret(conn, smsg))
}
