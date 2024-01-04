package user

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/findy-network/findy-common-go/agency/client"
	"github.com/findy-network/findy-common-go/dto"
	ops "github.com/findy-network/findy-common-go/grpc/ops/v1"
	"github.com/findy-network/findy-common-go/jwt"
	"github.com/findy-network/findy-common-go/rpc"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"google.golang.org/grpc"

	"github.com/lainio/err2/assert"
)

var baseCfg *rpc.ClientCfg

func Init(certPath, addr string, port int, insecure bool) {
	InitWithOpts(certPath, addr, port, insecure, nil)
}

func InitWithOpts(certPath, addr string, port int, insecure bool, opts []grpc.DialOption) {
	glog.V(3).Infoln(
		"\ncertPath:", certPath,
		"\naddr:", addr,
		"\nport:", port,
		"\ninsecure:", insecure,
	)
	if insecure && certPath == "" {
		glog.Warning("Establishing INSECURE connection to agency")
		baseCfg = client.BuildInsecureClientConnBase(addr, port, opts)
	} else {
		glog.V(1).Info("Establishing SECURE connection to agency")
		baseCfg = client.BuildClientConnBase(certPath, addr, port, opts)
	}
}

// User represents the user model
type User struct {
	Id            uint64
	Name          string // full email address
	PublicDIDSeed string // seed for the public DID
	DisplayName   string // shortened version of the Name
	DID           string
	//JWT         string // remove this from here and make a method
	Credentials []webauthn.Credential
}

func (u User) JWT() string {
	return jwt.BuildJWTWithLabel(u.DID, u.DisplayName)
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
func NewUser(name, displayName, seed string) *User {

	user := &User{}
	user.Id = randomUint64()
	user.Name = name
	user.DisplayName = displayName
	user.PublicDIDSeed = seed
	// user.credentials = []webauthn.Credential{}

	return user
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	try.To1(rand.Read(buf))
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
func (u *User) AllocateCloudAgent(adminID string, timeout time.Duration) (err error) {
	defer err2.Handle(&err)

	glog.V(1).Infoln("starting cloud agent allocation for", u.Name)

	// admin login?
	if adminID == u.Name {
		u.DID = adminID
		glog.V(1).Infoln("=== admin login used ===")
		return nil
	}

	// cloud agent already allocated?
	if u.DID != "" {
		assert.That(len(u.Credentials) > 1, "programming error")
		glog.V(1).Infoln("=== cloud agent already allocated")
		return nil
	}

	conn := client.TryOpen(adminID, baseCfg)
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	agencyClient := ops.NewAgencyServiceClient(conn)
	result := try.To1(agencyClient.Onboard(ctx, &ops.Onboarding{
		Email:         u.Name,
		PublicDIDSeed: u.PublicDIDSeed,
	}))
	glog.V(1).Infoln("result:", result.GetOk(), result.GetResult().CADID)
	if !result.GetOk() {
		return fmt.Errorf("cannot allocate cloud agent for %v", u.Name)
	}
	u.DID = result.GetResult().CADID

	return nil
}
