package authenticator

import (
	"encoding/binary"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/fxamacker/cbor"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
)

func MarshalData(data *protocol.AuthenticatorData) (json []byte, err error) {
	defer err2.Annotate("marshal authenticator data", &err)

	assert.Len(data.RPIDHash, 32, "wrong data length")

	json = make([]byte, 32+1+4, 37+lenAttestedCredentialData(data)+10)
	copy(json, data.RPIDHash)
	json[32] = byte(data.Flags)
	binary.BigEndian.PutUint32(json[33:], data.Counter)

	if data.Flags.HasAttestedCredentialData() {
		json = marshalAttestedCredentialData(json, data)
	}
	return json, nil
}

func marshalAttestedCredentialData(json []byte, data *protocol.AuthenticatorData) []byte {
	assert.Len(data.AttData.AAGUID, 16, "wrong AAGUID len(%d)", len(data.AttData.AAGUID))
	assert.True(len(data.AttData.CredentialID) != 0, "empty credential id")
	assert.True(len(data.AttData.CredentialPublicKey) != 0, "empty credential public key")

	json = append(json, data.AttData.AAGUID[:]...)

	idLength := uint16(len(data.AttData.CredentialID))
	json = json[:55]
	binary.BigEndian.PutUint16(json[53:], idLength)

	json = append(json, data.AttData.CredentialID[:]...)

	//json = append(json, marshalCredentialPublicKey(data.AttData.CredentialPublicKey)[:]...)
	json = append(json, data.AttData.CredentialPublicKey[:]...)

	return json
}

func lenAttestedCredentialData(data *protocol.AuthenticatorData) int {
	l := len(data.AttData.AAGUID) +
		len(data.AttData.CredentialID) +
		len(data.AttData.CredentialPublicKey)
	return l
}

func marshalCredentialPublicKey(keyBytes []byte) []byte {
	var m interface{}
	cbor.Unmarshal(keyBytes, &m)
	rawBytes, _ := cbor.Marshal(m)
	return rawBytes
}
