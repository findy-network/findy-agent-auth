package acator

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/lainio/err2"
)

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
