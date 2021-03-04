package enclave

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/findy-network/findy-agent-api/grpc/ops"
	"github.com/findy-network/findy-grpc/agency/client"
	"github.com/findy-network/findy-grpc/jwt"
	"github.com/findy-network/findy-grpc/rpc"
	"github.com/findy-network/findy-wrapper-go/dto"
	"github.com/golang/glog"
	"github.com/lainio/err2"
)

var baseCfg *rpc.ClientCfg

func Init(certPath, addr string, port int) {
	glog.V(3).Infoln("certPath:", certPath, "addr:", addr, "port:", port)
	baseCfg = client.BuildClientConnBase(certPath, addr, port, nil)
}

// User represents the user model
type User struct {
	Id          uint64
	Name        string // full email address
	DisplayName string // shortened version of the Name
	DID         string
	//JWT         string // remove this from here and make a method
	Credentials []webauthn.Credential
}

func (u User) JWT() string {
	return jwt.BuildJWT(u.DID)
}

func (u User) Key() []byte {
	return []byte(u.Name)
}

func (u User) Data() []byte {
	return dto.ToGOB(u)
}

func NewUserFromData(d []byte) *User {
	var u User
	dto.FromGOB(d, &u)
	return &u
}

// NewUser creates and returns a new User
func NewUser(name string, displayName string) *User {

	user := &User{}
	user.Id = randomUint64()
	user.Name = name
	user.DisplayName = displayName
	// user.credentials = []webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	err2.Try(rand.Read(buf))
	return binary.LittleEndian.Uint64(buf)
}

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, u.Id)
	return buf
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// CredentialExcludeList returns a CredentialDescriptor array filled
// with all the user's credentials
func (u User) CredentialExcludeList() []protocol.CredentialDescriptor {
	credentialExcludeList := make([]protocol.CredentialDescriptor, 0, len(u.Credentials))
	for _, cred := range u.Credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credentialExcludeList = append(credentialExcludeList, descriptor)
	}
	return credentialExcludeList
}

// AllocateCloudAgent allocates new cloud agent from the agency. adminID is part
// of the security for the current agency ecosystem. It must match what's
// configured to server side i.e. agency.
func (u *User) AllocateCloudAgent(adminID string) (err error) {
	defer err2.Return(&err)

	glog.V(1).Infoln("starting cloud agent allocation for", u.Name)

	conn := client.TryOpen(adminID, baseCfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	agencyClient := ops.NewAgencyClient(conn)
	result, err := agencyClient.Onboard(ctx, &ops.Onboarding{
		Email: u.Name,
	})
	err2.Check(err)
	glog.V(1).Infoln("result:", result.GetOk(), result.GetResult().CADID)
	if !result.GetOk() {
		return fmt.Errorf("cannot allocate cloud agent for %v", u.Name)
	}
	u.DID = result.GetResult().CADID

	return nil
}
