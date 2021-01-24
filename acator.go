package acator

import (
	"crypto/ecdsa"
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
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/lainio/err2"
)

var (
	Counter uint32
	AAGUID  = uuid.Must(uuid.Parse("12c85a48-4baf-47bd-b51f-f192871a1511"))
)

func Login(jsonStream io.Reader) (outStream io.Reader, err error) {
	defer err2.Annotate("login", &err)
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		defer err2.CatchTrace(func(err error) {
			glog.Error(err)
		})
		ca := tryReadAssertion(jsonStream)
		car := tryProcessLoginMessages(ca)
		err2.Check(json.NewEncoder(pw).Encode(car))
	}()
	return pr, nil
}

func tryProcessLoginMessages(ca *protocol.CredentialAssertion) (car *protocol.CredentialAssertionResponse) {
	Counter++
	aaGUIDBytes := err2.Bytes.Try(AAGUID.MarshalBinary())

	var priKey *ecdsa.PrivateKey
	var credID []byte
	for _, credential := range ca.Response.AllowedCredentials {
		if pk, err := cose.ParseSecretPrivateKey(credential.CredentialID); err == nil {
			credID = credential.CredentialID
			priKey = pk
			break
		}
	}
	if priKey == nil {
		err2.Check(fmt.Errorf("credential does not exist"))
	}

	key := cose.NewFromPrivateKey(priKey)
	RPIDHash := sha256.Sum256([]byte(ca.Response.RelyingPartyID))
	ccd := protocol.CollectedClientData{
		Type:      protocol.AssertCeremony,
		Challenge: base64.RawURLEncoding.EncodeToString(ca.Response.Challenge),
		Origin:    "http://localhost:8080",
	}
	ccdByteJson, _ := json.Marshal(ccd)

	authenticatorData := protocol.AuthenticatorData{
		RPIDHash: RPIDHash[:],
		Flags:    protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent,
		Counter:  Counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        credID,
			CredentialPublicKey: err2.Bytes.Try(key.Marshal()),
		},
		ExtData: nil,
	}
	authenticatorRawData := authenticator.TryMarshalData(&authenticatorData)

	clientDataHash := sha256.Sum256(ccdByteJson)

	sigData := append(authenticatorRawData, clientDataHash[:]...)
	sig := err2.Bytes.Try(key.Sign(sigData))

	car = &protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credID),
				Type: "public-key",
			},
			RawID:      credID,
			Extensions: nil,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJson},
			AuthenticatorData:     authenticatorRawData,
			Signature:             sig,
		},
	}
	return car
}

func Register(jsonStream io.Reader) (ccr *protocol.CredentialCreationResponse, err error) {
	defer err2.Annotate("register", &err)

	println(AAGUID.String())

	cred, err := NewCredentialCreation(jsonStream)
	err2.Check(err)
	Counter++
	aaGUIDBytes := err2.Bytes.Try(AAGUID.MarshalBinary())

	key := cose.Must(cose.New())

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
		Counter:  Counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        secretPrivateKey,
			CredentialPublicKey: err2.Bytes.Try(key.Marshal()),
		},
		ExtData: nil,
	}
	ao := authenticator.AttestationObject{
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

func tryReadAssertion(r io.Reader) (_ *protocol.CredentialAssertion) {
	var cr protocol.CredentialAssertion
	err2.Check(json.NewDecoder(r).Decode(&cr))
	return &cr
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
