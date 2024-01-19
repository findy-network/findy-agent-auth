package acator

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"

	"github.com/findy-network/findy-agent-auth/acator/authenticator"
	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

type Instance struct {
	Counter uint32
	AAGUID  uuid.UUID
	Origin  *url.URL
}

func useDefIfNot(i *Instance) *Instance {
	if i == nil {
		return defInstance
	}
	return i
}

var (
	defInstance = &Instance{
		Counter: 0,
		AAGUID:  uuid.Must(uuid.Parse("12c85a48-4baf-47bd-b51f-f192871a1511")),
		Origin:  try.To1(url.Parse(Origin)),
	}
	Origin = "http://localhost"
)

// SetDefInstanceOrigin sets the Origin. Mostly for tests.
func SetDefInstanceOrigin(s string) {
	Origin = s
	defInstance.Origin = try.To1(url.Parse(Origin))
}

// SetDefInstance sets default instance. Mostly for tests.
func SetDefInstance(i *Instance) {
	defInstance = i
}

// Login reads CredentialAssertion JSON from the input stream and same time
// process it and outputs CredentialAssertionResponse JSON to output stream.
func Login(i *Instance, jsonStream io.Reader) (outStream io.Reader, err error) {
	defer err2.Handle(&err, "login")
	pr, pw := io.Pipe()

	i = useDefIfNot(i)
	go func() {
		defer pw.Close()
		defer err2.Catch()

		ca := tryReadAssertion(jsonStream)
		car := tryBuildAssertionResponse(i, ca)
		try.To(json.NewEncoder(pw).Encode(car))
	}()
	return pr, nil
}

func tryBuildAssertionResponse(
	i *Instance,
	ca *protocol.CredentialAssertion,
) (car *protocol.CredentialAssertionResponse) {
	origin := try.To1(protocol.FullyQualifiedOrigin(i.Origin.String()))

	aaGUIDBytes := try.To1(i.AAGUID.MarshalBinary())

	var (
		found     bool
		keyHandle enclave.KeyHandle
		credID    []byte
	)
	for _, credential := range ca.Response.AllowedCredentials {
		if found, keyHandle = enclave.Store.IsKeyHandle(credential.CredentialID); found {
			credID = credential.CredentialID
			break
		}
	}
	assert.That(found, "authenticator not found")
	assert.INotNil(keyHandle, "key handle cannot be nil")

	RPIDHash := sha256.Sum256([]byte(ca.Response.RelyingPartyID))
	ccd := protocol.CollectedClientData{
		Type:      protocol.AssertCeremony,
		Challenge: base64.RawURLEncoding.EncodeToString(ca.Response.Challenge),
		Origin:    origin,
	}
	ccdByteJSON, _ := json.Marshal(ccd)

	authenticatorData := protocol.AuthenticatorData{
		RPIDHash: RPIDHash[:],
		Flags:    protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent,
		Counter:  i.Counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        credID,
			CredentialPublicKey: try.To1(keyHandle.CBORPublicKey()),
		},
		ExtData: nil,
	}
	authenticatorRawData := authenticator.TryMarshalData(&authenticatorData)

	clientDataHash := sha256.Sum256(ccdByteJSON)

	sigData := append(authenticatorRawData, clientDataHash[:]...)
	sig := try.To1(keyHandle.Sign(sigData))

	car = &protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credID),
				Type: "public-key",
			},
			RawID: credID,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJSON},
			AuthenticatorData:     authenticatorRawData,
			Signature:             sig,
		},
	}
	return car
}

// RegisterAsync reads CredentialCreation JSON from the input stream and same time
// process it and outputs CredentialCreationResponse JSON to output stream.
func RegisterAsync(i *Instance, jsonStream io.Reader) (outStream io.Reader, err error) {
	pr, pw := io.Pipe()

	i = useDefIfNot(i)
	go func() {
		defer pw.Close()
		defer err2.Catch()

		cred := tryReadCreation(jsonStream)
		ccr := tryBuildCreationResponse(i, cred)
		try.To(json.NewEncoder(pw).Encode(ccr))
	}()
	return pr, nil
}

// Register reads CredentialCreation JSON from the input stream and same time
// process it and outputs CredentialCreationResponse JSON to output stream.
func Register(i *Instance, jsonStream io.Reader) (outStream io.Reader, err error) {
	defer err2.Handle(&err)

	i = useDefIfNot(i)
	cred := tryReadCreation(jsonStream)
	ccr := tryBuildCreationResponse(i, cred)
	b := try.To1(json.Marshal(ccr))
	return bytes.NewReader(b), nil
}

func tryBuildCreationResponse(
	i *Instance,
	creation *protocol.CredentialCreation,
) (
	ccr *protocol.CredentialCreationResponse,
) {
	origin := try.To1(protocol.FullyQualifiedOrigin(i.Origin.String()))
	aaGUIDBytes := try.To1(i.AAGUID.MarshalBinary())
	keyHandle := try.To1(enclave.Store.NewKeyHandle())
	RPIDHash := sha256.Sum256([]byte(creation.Response.RelyingParty.ID))

	khID := keyHandle.ID()
	flags := protocol.FlagAttestedCredentialData | protocol.FlagUserVerified | protocol.FlagUserPresent
	authenticatorData := protocol.AuthenticatorData{
		RPIDHash: RPIDHash[:],
		Flags:    flags,
		Counter:  i.Counter,
		AttData: protocol.AttestedCredentialData{
			AAGUID:              aaGUIDBytes,
			CredentialID:        khID,
			CredentialPublicKey: try.To1(keyHandle.CBORPublicKey()),
		},
		ExtData: nil,
	}
	ao := authenticator.AttestationObject{
		RawAuthData:  authenticator.TryMarshalData(&authenticatorData),
		Format:       "none",
		AttStatement: map[string]any{},
	}
	aoByteCBOR := try.To1(cbor.Marshal(ao))

	ccd := protocol.CollectedClientData{
		Type:         protocol.CreateCeremony,
		Challenge:    creation.Response.Challenge.String(),
		Origin:       origin,
		TokenBinding: nil,
		Hint:         "",
	}
	assert.NotEmpty(ccd.Challenge)

	ccdByteJSON := try.To1(json.Marshal(ccd))
	assert.That(checkClientData(ccdByteJSON))

	ccr = &protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(khID),
				Type: "public-key",
			},
			RawID: khID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: ccdByteJSON},
			AttestationObject:     aoByteCBOR,
		},
	}
	assert.Equal(`"`+ccr.Credential.ID+`"`, string(try.To1(ccr.RawID.MarshalJSON())))

	glog.V(13).Infof("\n%s ==\n%s", ccr.Credential.ID, string(try.To1(ccr.RawID.MarshalJSON())))
	strCcr := string(try.To1(json.MarshalIndent(ccr, "", "\t")))
	glog.V(13).Infoln("CCR json:\n", strCcr)
	return ccr
}

func checkClientData(d []byte) bool {
	var ccd protocol.CollectedClientData
	try.To(json.Unmarshal(d, &ccd))
	return ccd.Challenge != ""
}

func tryReadCreation(r io.Reader) *protocol.CredentialCreation {
	b := try.To1(io.ReadAll(r))
	//var buf bytes.Buffer
	//r = io.TeeReader(r, &buf)
	var creation protocol.CredentialCreation
	//try.To(json.NewDecoder(r).Decode(&creation))
	try.To(json.Unmarshal(b, &creation))

	//	var m map[string]any
	//	try.To(json.NewDecoder(&buf).Decode(&m))
	//	fmt.Printf("\n%v\n", m)
	//	assert.MKeyExists(m, "timeout")
	//	c := assert.MKeyExists(m, "challenge").(string)
	//	assert.NotEmpty(c)
	//	fmt.Printf("\n%v\n", c)

	//assert.SNotEmpty(creation.Response.Challenge)
	assert.NotEmpty(creation.Response.User.Name, "check envelope JSON")
	assert.NotEmpty(creation.Response.Challenge.String(), "check envelope JSON")
	return &creation
}

func tryReadAssertion(r io.Reader) *protocol.CredentialAssertion {
	var cr protocol.CredentialAssertion
	try.To(json.NewDecoder(r).Decode(&cr))
	return &cr
}
