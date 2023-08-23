package grpcenclave

import (
	se "github.com/findy-network/findy-agent-auth/acator/enclave"
	pb "github.com/findy-network/findy-common-go/grpc/authn/v1"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
)

type Enclave struct {
	*pb.Cmd

	CmdID   int64
	OutChan chan *pb.CmdStatus
	InChan  chan *pb.SecretMsg
}

type keyHandle struct {
	*Enclave
	handle int64
}

// NewKeyHandle creates a new key handle for the enclave. The enclave is
// stateless, which means that only the master key is needed. The master key is
// stored to every key handle to maintain statelessness.
func (e *Enclave) NewKeyHandle() (kh se.KeyHandle, err error) {
	defer err2.Handle(&err)

	glog.V(3).Infoln("send question in new key handle")
	e.OutChan <- &pb.CmdStatus{
		CmdID:   e.CmdID,
		Type:    pb.CmdStatus_STATUS,
		CmdType: e.GetType(),
		SecType: pb.SecretMsg_NEW_HANDLE,
		Info: &pb.CmdStatus_Enclave{ // TODO: this could be nil
			Enclave: &pb.SecretMsg_EnclaveMsg{
				CredID: []byte{},
			},
		},
	}
	glog.V(3).Infoln("wait answer in NewKeyHandle")

	reply := <-e.InChan
	assert.NotEqual(reply.GetType(), pb.SecretMsg_ERROR)
	assert.Equal(reply.GetType(), pb.SecretMsg_NEW_HANDLE)
	kh = &keyHandle{
		Enclave: e,
		handle:  reply.GetHandle().GetID(),
	}

	glog.V(3).Infoln("NewKeyHandle ready")
	return kh, nil
}

// IsKeyHandle tells if given byte slice really is key handle from the current
// enclave.
func (e *Enclave) IsKeyHandle(credID []byte) (ok bool, kh se.KeyHandle) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Errorf("error: is key handle: %v", err)
		ok, kh = false, nil
	}))

	glog.V(3).Infoln("send question IsKeyHandle")
	e.OutChan <- &pb.CmdStatus{
		CmdID:   e.CmdID,
		Type:    pb.CmdStatus_STATUS,
		CmdType: e.GetType(),
		SecType: pb.SecretMsg_IS_KEY_HANDLE,
		Info: &pb.CmdStatus_Enclave{
			Enclave: &pb.SecretMsg_EnclaveMsg{
				CredID: credID,
			},
		},
	}
	glog.V(3).Infoln("wait answer IsKeyHandle")

	reply := <-e.InChan
	assert.NotEqual(reply.GetType(), pb.SecretMsg_ERROR)
	assert.Equal(reply.GetType(), pb.SecretMsg_IS_KEY_HANDLE)
	kh = &keyHandle{
		Enclave: e,
		handle:  reply.GetHandle().GetID(),
	}

	glog.V(3).Infoln("IsKeyHandle TRUE")
	return true, kh
}

// ID returns ENCRYPTED presentation of X509 encoded byte slice whole key, which
// means that it includes the private key as well. That means that the whole key
// pair can be restored into this same Enclave (master key is used for the
// encryption).
func (h *keyHandle) ID() (id []byte) {
	glog.V(3).Infoln("send question ID")
	h.OutChan <- &pb.CmdStatus{
		CmdID:   h.CmdID,
		Type:    pb.CmdStatus_STATUS,
		CmdType: h.GetType(),
		SecType: pb.SecretMsg_ID,
		Info: &pb.CmdStatus_Handle{
			Handle: &pb.SecretMsg_HandleMsg{
				ID: h.handle,
			},
		},
	}

	glog.V(3).Infoln("waiting question ID")
	reply := <-h.InChan
	assert.NotEqual(reply.GetType(), pb.SecretMsg_ERROR)
	assert.Equal(reply.GetType(), pb.SecretMsg_ID)
	id = reply.GetHandle().GetData()
	glog.V(3).Infoln("READY question ID")
	return
}

// CBORPublicKey returns CBOR marshaled byte slice presentation of the public
// key or error.
func (h *keyHandle) CBORPublicKey() (pk []byte, err error) {
	defer err2.Handle(&err)

	glog.V(3).Infoln("send question CBORPublicKey")
	h.OutChan <- &pb.CmdStatus{
		CmdID:   h.CmdID,
		Type:    pb.CmdStatus_STATUS,
		CmdType: h.GetType(),
		SecType: pb.SecretMsg_CBOR_PUB_KEY,
		Info: &pb.CmdStatus_Handle{
			Handle: &pb.SecretMsg_HandleMsg{
				ID: h.handle,
			},
		},
	}

	glog.V(3).Infoln("waiting question CBORPublicKey")
	reply := <-h.InChan
	assert.NotEqual(reply.GetType(), pb.SecretMsg_ERROR)
	assert.Equal(reply.GetType(), pb.SecretMsg_CBOR_PUB_KEY)
	glog.V(3).Infoln("question CBORPublicKey ready")
	return reply.GetHandle().GetData(), nil
}

// Sign function signs then given byte slice and returns the signature or error.
func (h *keyHandle) Sign(d []byte) (s []byte, err error) {
	defer err2.Handle(&err)

	glog.V(3).Infoln("send question Sign")
	h.OutChan <- &pb.CmdStatus{
		CmdID:   h.CmdID,
		Type:    pb.CmdStatus_STATUS,
		CmdType: h.GetType(),
		SecType: pb.SecretMsg_SIGN,
		Info: &pb.CmdStatus_Handle{
			Handle: &pb.SecretMsg_HandleMsg{
				ID:   h.handle,
				Data: d,
			},
		},
	}

	glog.V(3).Infoln("wait question Sign")
	reply := <-h.InChan
	assert.NotEqual(reply.GetType(), pb.SecretMsg_ERROR)
	assert.Equal(reply.GetType(), pb.SecretMsg_SIGN)
	glog.V(3).Infoln("question Sign ready")
	return reply.GetHandle().GetSign(), nil
}

// Verify verifies the given data and signature.
func (h *keyHandle) Verify(data, sig []byte) (ok bool) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Errorf("error: verify: %v", err)
		ok = false
	}))

	h.OutChan <- &pb.CmdStatus{
		CmdID:   h.CmdID,
		Type:    pb.CmdStatus_STATUS,
		CmdType: h.GetType(),
		SecType: pb.SecretMsg_VERIFY,
		Info: &pb.CmdStatus_Handle{
			Handle: &pb.SecretMsg_HandleMsg{
				ID:   h.handle,
				Data: data,
				Sign: sig,
			},
		},
	}

	reply := <-h.InChan
	assert.NotEqual(reply.GetType(), pb.SecretMsg_ERROR)
	assert.Equal(reply.GetType(), pb.SecretMsg_SIGN)
	assert.Equal(reply.GetHandle().GetID(), h.handle)

	return true
}
