package credential

import "github.com/duo-labs/webauthn/protocol"

type Credential struct {
	protocol.PublicKeyCredential
}

func (c *Credential) PKBytes() []byte {
	return []byte{1,2}
}

func New(creation *protocol.CredentialCreation) *Credential {
	return &Credential{}
}
