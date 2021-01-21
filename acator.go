package acator

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/findy-network/findy-grpc/acator/credential"
	"github.com/fxamacker/cbor"
	"github.com/google/uuid"
	"github.com/lainio/err2"
)

var (
	counter uint32
	aaGUID  = uuid.New()
)

func Register(s string) (ccr *protocol.CredentialCreationResponse) {
	cred, _ := NewCreation(s)
	counter++
	aaGUIDBytes, _ := aaGUID.MarshalBinary()
	c := credential.New(&cred)

	RPID := sha256.Sum256([]byte(cred.Response.RelyingParty.ID))
	ccd := protocol.CollectedClientData{
		Type:         protocol.CreateCeremony,
		Challenge:    base64.RawURLEncoding.EncodeToString(cred.Response.Challenge),
		Origin:       "http://localhost:8080",
		TokenBinding: nil,
		Hint:         "",
	}
	ccdByteJson, _ := json.Marshal(ccd)
	ao := protocol.AttestationObject{
		AuthData: protocol.AuthenticatorData{
			RPIDHash: RPID[:],
			Flags:    protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent,
			Counter:  counter,
			AttData: protocol.AttestedCredentialData{
				AAGUID:              aaGUIDBytes,
				CredentialID:        c.RawID,
				CredentialPublicKey: c.PKBytes(),
			},
			ExtData: nil,
		},
		RawAuthData:  nil,
		Format:       "none",
		AttStatement: nil,
	}
	aoByteCBOR, _ := cbor.Marshal(ao)

	ccr = &protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{},
			RawID:      nil,
			Extensions: nil,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJson},
			AttestationObject:     aoByteCBOR,
		},
	}
	return
}

func NewCreation(s string) (cred protocol.CredentialCreation, err error) {
	defer err2.Annotate("new creation", &err)

	err2.Check(json.Unmarshal([]byte(s), &cred))
	return cred, nil
}

func NewAssertion(s string) (cred *protocol.CredentialAssertion, err error) {
	defer err2.Annotate("new assertion", &err)

	var cr protocol.CredentialAssertion
	err2.Check(json.Unmarshal([]byte(s), &cr))
	return &cr, nil
}

func BuildResponse(cred protocol.CredentialCreation) (car protocol.CredentialAssertionResponse, err error) {
	//tmp := protocol.AttestationObject{}
	car = protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   "",
				Type: "",
			},
			RawID:      nil,
			Extensions: nil,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{},
			AuthenticatorData:     nil,
			Signature:             nil,
			UserHandle:            nil,
		},
	}
	return car, nil
}

func ParseResponse(s string) (*protocol.ParsedCredentialCreationData, error) {
	r := strings.NewReader(s)
	return protocol.ParseCredentialCreationResponseBody(r)
}

func ParseAssertionResponse(s string) (*protocol.ParsedCredentialAssertionData, error) {
	r := strings.NewReader(s)
	return protocol.ParseCredentialRequestResponseBody(r)
}

func AcatorUnmarshal(d []byte) error {
	ad := protocol.AuthenticatorData{}
	err := ad.Unmarshal(d)
	b, err := json.MarshalIndent(ad, "", "\t")
	fmt.Printf("%s\n", b)
	return err
}
