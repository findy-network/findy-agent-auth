package acator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"testing"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/findy-network/findy-agent-auth/acator/authenticator"
	"github.com/findy-network/findy-agent-auth/acator/cose"
	"github.com/lainio/err2/assert"
)

// Credential creation/Register
var challengeJSON = `{
  "publicKey": {
    "challenge": "7vH6L70QspI4ToHZ6gTJLj74jQ9jj/AzlIQkSlkZX8E=",
    "rp": {
      "name": "Foobar Corp.",
      "id": "localhost"
    },
    "user": {
      "name": "debug1",
      "displayName": "debug1",
      "id": "nsWi6Nr9u8nAAQ=="
    },
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      },
      {
        "type": "public-key",
        "alg": -35
      },
      {
        "type": "public-key",
        "alg": -36
      },
      {
        "type": "public-key",
        "alg": -257
      },
      {
        "type": "public-key",
        "alg": -258
      },
      {
        "type": "public-key",
        "alg": -259
      },
      {
        "type": "public-key",
        "alg": -37
      },
      {
        "type": "public-key",
        "alg": -38
      },
      {
        "type": "public-key",
        "alg": -39
      },
      {
        "type": "public-key",
        "alg": -8
      }
    ],
    "authenticatorSelection": {
      "requireResidentKey": false,
      "userVerification": "preferred"
    },
    "timeout": 60000
  }
}
`

var challengeResponseJSON = `{
  "id": "Ae3OpoEHZefub0h_5xMZm4WY1oIW8RU1f2xh49XqiQ9o530QPp6B09ZGXt0GyHas32YRrRKNJoA",
  "rawId": "Ae3OpoEHZefub0h_5xMZm4WY1oIW8RU1f2xh49XqiQ9o530QPp6B09ZGXt0GyHas32YRrRKNJoA",
  "type": "public-key",
  "response": {
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVi8SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFYALcd63OAAI1vMYKZIsLJfHwVQMAOAHtzqaBB2Xn7m9If-cTGZuFmNaCFvEVNX9sYePV6okPaOd9ED6egdPWRl7dBsh2rN9mEa0SjSaApQECAyYgASFYIIcEZtPD-t7SgrBCqo8DmkzK-5hPRC7Agr9-4w2Egc3EIlggArnWSfgKmTTjWiOvtNu9Ck7jJDJpVJvff7CX_xQhzbk",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiN3ZINkw3MFFzcEk0VG9IWjZnVEpMajc0alE5ampfQXpsSVFrU2xrWlg4RSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0"
  }
}
`

// ==== assertion/Login
// credentialRequestOptions
var _ = `{
  "publicKey": {
    "challenge": "yifGGzsupyIW3xxZoL09vEbJQYBrQaarZf4CN8GUvWE=",
    "timeout": 60000,
    "rpId": "localhost",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "Ae3OpoEHZefub0h/5xMZm4WY1oIW8RU1f2xh49XqiQ9o530QPp6B09ZGXt0GyHas32YRrRKNJoA="
      }
    ]
  }
}
`

var credentialRequestOptionsFmt = `{
  "publicKey": {
    "challenge": "yifGGzsupyIW3xxZoL09vEbJQYBrQaarZf4CN8GUvWE=",
    "timeout": 60000,
    "rpId": "localhost",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "%s"
      }
    ]
  }
}
`

var authenticatorAssertionResponse = `{
  "id": "Ae3OpoEHZefub0h_5xMZm4WY1oIW8RU1f2xh49XqiQ9o530QPp6B09ZGXt0GyHas32YRrRKNJoA",
  "rawId": "Ae3OpoEHZefub0h_5xMZm4WY1oIW8RU1f2xh49XqiQ9o530QPp6B09ZGXt0GyHas32YRrRKNJoA",
  "type": "public-key",
  "response": {
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFYAU-Hg",
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoieWlmR0d6c3VweUlXM3h4Wm9MMDl2RWJKUVlCclFhYXJaZjRDTjhHVXZXRSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
    "signature": "MEQCIEXR3OAmve4jJoER6-HR1qVQrCkuj9xFapZqdj13Ms6qAiB8Vj1QuZog67zpzt8ywVwK8iqViaH34y9AXPKTh1JImA",
    "userHandle": "nsWi6Nr9u8nAAQ"
  }
}
`

func TestRegister(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	originURL, _ := url.Parse("http://localhost:8080")
	Origin = *originURL

	r := strings.NewReader(challengeJSON)
	js, err := Register(r)
	assert.NoError(err)
	assert.INotNil(js)

	ccd, err := protocol.ParseCredentialCreationResponseBody(js)
	assert.NoError(err)
	assert.INotNil(ccd)
}

func TestLogin(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	originURL, _ := url.Parse("http://localhost:8080")
	Origin = *originURL

	credID := "QABRwuCGuynqf0lf35FK-CG-PY_WXai1oCzIZdIbY4S-81SMwZg1hD_V75cWyPwrGmFS4NpVegzMg8c-XnIBYPvmsl0hmkoxMCPDe7tKgV0kcSBC2Fy-BN8B22Ftt78CrZQUbYMJruutTWEp818XaVH9KDlRuV4s9k0G-T23lMUjqJHzUn-gfMbuP1uuVILV6rQu6kw"
	data, err := base64.RawURLEncoding.DecodeString(credID)
	assert.NoError(err)

	newStr := base64.StdEncoding.EncodeToString(data)
	assert.NoError(err)
	credID = newStr
	credReq := fmt.Sprintf(credentialRequestOptionsFmt, credID)
	car, err := Login(strings.NewReader(credReq))
	assert.NoError(err)
	assert.INotNil(car)

	pcad, err := protocol.ParseCredentialRequestResponseBody(car)
	assert.NoError(err)
	assert.INotNil(pcad)

	credentialBytes := pcad.Response.AuthenticatorData.AttData.CredentialPublicKey
	err = pcad.Verify("yifGGzsupyIW3xxZoL09vEbJQYBrQaarZf4CN8GUvWE",
		"localhost", "http://localhost:8080", "", false,
		credentialBytes)
	assert.NoError(err)
}

func TestParseAssertionResponse(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	ccd, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(challengeResponseJSON))
	assert.NoError(err)

	ad, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(authenticatorAssertionResponse))
	assert.NoError(err)

	// Step 15. Let hash be the result of computing a hash over the cData using SHA-256.
	clientDataHash := sha256.Sum256(ad.Raw.AssertionResponse.ClientDataJSON)

	// Step 16. Using the credential public key looked up in step 3, verify that sig is
	// a valid signature over the binary concatenation of authData and hash.

	sigData := append(ad.Raw.AssertionResponse.AuthenticatorData, clientDataHash[:]...)

	credentialBytes := ccd.Response.AttestationObject.AuthData.AttData.CredentialPublicKey

	coseKey, err := cose.NewFromData(credentialBytes)
	assert.NoError(err)
	valid := coseKey.Verify(sigData, ad.Response.Signature)
	assert.That(valid)
	keyData, _ := coseKey.Marshal()
	assert.SLen(credentialBytes, len(keyData))

	key, err := webauthncose.ParsePublicKey(keyData)
	assert.NoError(err)
	k, ok := key.(webauthncose.EC2PublicKeyData)
	assert.That(ok)
	pubkey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(k.XCoord),
		Y:     big.NewInt(0).SetBytes(k.YCoord),
	}

	valid = cose.VerifyHashSig(pubkey, sigData, ad.Response.Signature)
	assert.NoError(err)
	assert.That(valid)

	valid, err = webauthncose.VerifySignature(key, sigData, ad.Response.Signature)
	assert.NoError(err)
	assert.That(valid)

	err = ad.Verify("yifGGzsupyIW3xxZoL09vEbJQYBrQaarZf4CN8GUvWE",
		"localhost", "http://localhost:8080", "", false,
		credentialBytes)
	assert.NoError(err)

	authenticatorJSON, err := authenticator.MarshalData(&ad.Response.AuthenticatorData)
	assert.NoError(err)
	assert.DeepEqual(authenticatorJSON, []uint8(ad.Raw.AssertionResponse.AuthenticatorData))
}

func TestParseResponse(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	ccd, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(challengeResponseJSON))
	assert.NoError(err)
	assert.INotNil(ccd)

	js, err := authenticator.MarshalData(&ccd.Response.AttestationObject.AuthData)
	assert.NoError(err)
	assert.SLen(js, len(ccd.Response.AttestationObject.RawAuthData))
}
