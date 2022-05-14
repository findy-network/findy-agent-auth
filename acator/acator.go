package acator

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/findy-network/findy-agent-auth/acator/authenticator"
	"github.com/findy-network/findy-agent-auth/acator/cose"
	"github.com/fxamacker/cbor/v2"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/lainio/err2"
)

var (
	Counter uint32
	AAGUID  = uuid.Must(uuid.Parse("12c85a48-4baf-47bd-b51f-f192871a1511"))
	Origin  url.URL
)

// Login reads CredentialAssertion JSON from the input stream and same time
// process it and outputs CredentialAssertionResponse JSON to output stream.
func Login(jsonStream io.Reader) (outStream io.Reader, err error) {
	defer err2.Annotate("login", &err)
	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		defer err2.CatchTrace(func(err error) {
			glog.Error(err)
		})
		ca := tryReadAssertion(jsonStream)
		car := tryBuildAssertionResponse(ca)
		try.To1(json.NewEncoder(pw).Encode(car))
	}()
	return pr, nil
}

func tryBuildAssertionResponse(ca *protocol.CredentialAssertion) (car *protocol.CredentialAssertionResponse) {
	origin := protocol.FullyQualifiedOrigin(&Origin)

	aaGUIDBytes := try.To1(AAGUID.MarshalBinary())

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
		try.To1(fmt.Errorf("credential does not exist"))
	}

	key := cose.NewFromPrivateKey(priKey)
	RPIDHash := sha256.Sum256([]byte(ca.Response.RelyingPartyID))
	ccd := protocol.CollectedClientData{
		Type:      protocol.AssertCeremony,
		Challenge: base64.RawURLEncoding.EncodeToString(ca.Response.Challenge),
		Origin:    origin,
	}
	ccdByteJson, _ := json.Marshal(ccd)

	authenticatorData := protocol.AuthenticatorData{
		RPIDHash: RPIDHash[:],
		Flags:    protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent,
		Counter:  Counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        credID,
			CredentialPublicKey: try.To1(key.Marshal()),
		},
		ExtData: nil,
	}
	authenticatorRawData := authenticator.TryMarshalData(&authenticatorData)

	clientDataHash := sha256.Sum256(ccdByteJson)

	sigData := append(authenticatorRawData, clientDataHash[:]...)
	sig := try.To1(key.Sign(sigData))

	car = &protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credID),
				Type: "public-key",
			},
			RawID: credID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJson},
			AuthenticatorData:     authenticatorRawData,
			Signature:             sig,
		},
	}
	return car
}

// Register reads CredentialCreation JSON from the input stream and same time
// process it and outputs CredentialCreationResponse JSON to output stream.
func Register(jsonStream io.Reader) (outStream io.Reader, err error) {
	defer err2.Annotate("register", &err)

	pr, pw := io.Pipe()

	go func() {
		defer pw.Close()
		defer err2.CatchTrace(func(err error) {
			glog.Error(err)
		})
		cred := tryReadCreation(jsonStream)
		ccr := tryBuildCreationResponse(cred)
		try.To1(json.NewEncoder(pw).Encode(ccr))
	}()
	return pr, nil

}

func tryBuildCreationResponse(creation *protocol.CredentialCreation) (ccr *protocol.CredentialCreationResponse) {
	origin := protocol.FullyQualifiedOrigin(&Origin)
	aaGUIDBytes := try.To1(AAGUID.MarshalBinary())
	newPrivKey := cose.Must(cose.New())
	RPIDHash := sha256.Sum256([]byte(creation.Response.RelyingParty.ID))

	ccd := protocol.CollectedClientData{
		Type:         protocol.CreateCeremony,
		Challenge:    base64.RawURLEncoding.EncodeToString(creation.Response.Challenge),
		Origin:       origin,
		TokenBinding: nil,
		Hint:         "",
	}
	ccdByteJson := try.To1(json.Marshal(ccd))

	secretPrivateKey := newPrivKey.TryMarshalSecretPrivateKey()
	flags := protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent
	authenticatorData := protocol.AuthenticatorData{
		RPIDHash: RPIDHash[:],
		Flags:    flags,
		Counter:  Counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        secretPrivateKey,
			CredentialPublicKey: try.To1(newPrivKey.Marshal()),
		},
		ExtData: nil,
	}
	ao := authenticator.AttestationObject{
		RawAuthData:  authenticator.TryMarshalData(&authenticatorData),
		Format:       "none",
		AttStatement: nil,
	}
	aoByteCBOR := try.To1(cbor.Marshal(ao))

	ccr = &protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(secretPrivateKey),
				Type: "public-key",
			},
			RawID: secretPrivateKey,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJson},
			AttestationObject:     aoByteCBOR,
		},
	}
	return ccr
}

func tryReadCreation(r io.Reader) *protocol.CredentialCreation {
	var creation protocol.CredentialCreation
	try.To1(json.NewDecoder(r).Decode(&creation))
	return &creation
}

func tryReadAssertion(r io.Reader) *protocol.CredentialAssertion {
	var cr protocol.CredentialAssertion
	try.To1(json.NewDecoder(r).Decode(&cr))
	return &cr
}
