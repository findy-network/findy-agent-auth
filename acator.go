package acator

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/findy-network/findy-grpc/acator/authenticator"
	"github.com/findy-network/findy-grpc/acator/cose"
	"github.com/fxamacker/cbor"
	"github.com/google/uuid"
	"github.com/lainio/err2"
)

var (
	counter uint32
	aaGUID  = uuid.New()
)

func Register(jsonStream io.Reader) (ccr *protocol.CredentialCreationResponse, err error) {
	defer err2.Annotate("register", &err)

	cred, _ := NewCredentialCreation(jsonStream)
	counter++
	aaGUIDBytes := err2.Bytes.Try(aaGUID.MarshalBinary())

	key := cose.TryNew()

	RPIDHash := sha256.Sum256([]byte(cred.Response.RelyingParty.ID))
	ccd := protocol.CollectedClientData{
		Type:         protocol.CreateCeremony,
		Challenge:    base64.RawURLEncoding.EncodeToString(cred.Response.Challenge),
		Origin:       "http://localhost:8080",
		TokenBinding: nil,
		Hint:         "",
	}
	ccdByteJson, _ := json.Marshal(ccd)
	secretPrivateKey := key.TryMarshalSecretPrivateKey()
	authenticatorData := protocol.AuthenticatorData{
		RPIDHash: RPIDHash[:],
		Flags:    protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent,
		Counter:  counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        secretPrivateKey,
			CredentialPublicKey: key.TryMarshal(),
		},
		ExtData: nil,
	}
	ao := authenticator.AttestationObject{
		//AuthData:     authenticatorData,
		RawAuthData:  authenticator.TryMarshalData(&authenticatorData),
		Format:       "none",
		AttStatement: nil,
	}
	aoByteCBOR, _ := cbor.Marshal(ao)

	ccr = &protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(secretPrivateKey),
				Type: "public-key",
			},
			RawID:      secretPrivateKey,
			Extensions: nil,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJson},
			AttestationObject:     aoByteCBOR,
		},
	}
	return
}

func NewCredentialCreation(r io.Reader) (cred protocol.CredentialCreation, err error) {
	defer err2.Annotate("new creation", &err)

	err2.Check(json.NewDecoder(r).Decode(&cred))
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
