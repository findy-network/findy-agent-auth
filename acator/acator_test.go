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

	"github.com/findy-network/findy-agent-auth/acator/authenticator"
	"github.com/findy-network/findy-agent-auth/acator/cose"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/lainio/err2/assert"
)

// Credential creation/Register
var _ = `{
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

/*
Test_myHandle_Sign/simple|114 error| ID as different round 0:
[181 200 6 0 39 82 176 72 235 122 209 147 250 32 132 69 119 246 237 225 102 196 193 169 226 29 227 143 127 49 133 5 242 101 154 23 180 56 92 5 152 194 108 252 66 214 212 203 25 52 244 18 144 170 172 129 163 89 11 213 3 109 139 104 8 228 106 249 175 64 245 241 151 246 238 204 239 222 20 213 213 65 60 178 219 0 89 59 92 254 27 93 107 56 198 231 160 131 104 119 44 116 53 193 123 82 55 28 167 23 123 89 243 63 1 46 1 0 29 220 245 133 245 95 178 235 146 3 69 160 138 86 250 22 28 162 150 64 156 4 182 240 114 208 223 174 75 5 77],
[53 236 194 154 182 9 38 231 126 211 21 53 212 210 10 77 80 212 101 234 245 158 69 246 217 225 71 163 206 136 118 12 7 70 234 117 244 213 54 74 151 55 104 218 74 178 17 64 232 28 141 58 172 225 91 74 3 231 155 178 50 212 152 149 231 122 145 56 183 126 35 227 82 188 60 248 172 238 5 87 96 194 71 63 130 62 0 126 202 206 183 5 18 30 127 218 234 229 108 222 22 38 16 77 137 96 100 179 132 204 199 226 148 31 175 187 241 87 192 129 191 98
*/

func TestRegister(t *testing.T) {
	type args struct {
		registerOptions string
		challenge       string
		rpOrigin        string
		rpID            string
	}
	tests := []struct {
		name   string
		args   args
		wantOK bool
	}{
		//		{"simple",
		//			args{challengeJSON, "7vH6L70QspI4ToHZ6gTJLj74jQ9jj/AzlIQkSlkZX8E=",
		//				"http://localhost", "Foobar Corp."},
		//			false,
		//		},
		{"from webauthn.io",
			args{webauthnIoChallenge,
				"wYRL_d6mbgou6Jh5ny3-UJa0yJlkXpX2CmngXVMbcPnVK0XOrBl8Q6zunD20vEMiRJ4RsCMYbX8ZbjwQ34QiAQ",
				"https://webauthn.io", "webauthn.io"},
			true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.PushTester(t)
			defer assert.PopTester()

			// r := strings.NewReader(tt.args.registerOptions)
			// var m map[string]any
			// err := json.NewDecoder(r).Decode(&m)
			// assert.NoError(err)
			originURL, _ := url.Parse(tt.args.rpOrigin)
			Origin = *originURL
			r := strings.NewReader(tt.args.registerOptions)
			js, err := Register(r)
			assert.NoError(err)
			assert.INotNil(js)

			ccd, err := protocol.ParseCredentialCreationResponseBody(js)
			if tt.wantOK {
				assert.NoError(err)
				assert.NotNil(ccd)
				// Verify(storedChallenge string, verifyUser bool, relyingPartyID string, relyingPartyOrigin string) error
				err := ccd.Verify(ccd.Response.CollectedClientData.Challenge,
					false, tt.args.rpID, []string{tt.args.rpOrigin})
				assert.NoError(err)
			}
		})
	}
}

func TestLogin(t *testing.T) {
	t.Skip("new go-webauthn")

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
	assert.NotNil(pcad)

	credentialBytes := pcad.Response.AuthenticatorData.AttData.CredentialPublicKey
	err = pcad.Verify("yifGGzsupyIW3xxZoL09vEbJQYBrQaarZf4CN8GUvWE",
		"localhost", []string{"http://localhost:8080"}, "", false,
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
		"localhost", []string{"http://localhost:8080"}, "", false,
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
	assert.NotNil(ccd)

	js, err := authenticator.MarshalData(&ccd.Response.AttestationObject.AuthData)
	assert.NoError(err)
	assert.SLen(js, len(ccd.Response.AttestationObject.RawAuthData))
}

var webauthnIoChallenge = `{"publicKey":{"rp": {"name": "webauthn.io", "id": "webauthn.io"}, "user": {"id": "ZW1wcHU", "name": "emppu", "displayName": "emppu"}, "challenge": "wYRL_d6mbgou6Jh5ny3-UJa0yJlkXpX2CmngXVMbcPnVK0XOrBl8Q6zunD20vEMiRJ4RsCMYbX8ZbjwQ34QiAQ", "pubKeyCredParams": [{"type": "public-key", "alg": -7}], "timeout": 60000, "excludeCredentials": [], "authenticatorSelection": {"authenticatorAttachment": "cross-platform", "residentKey": "preferred", "requireResidentKey": false, "userVerification": "preferred"}, "attestation": "direct", "extensions": {"credProps": true}}}`

var _ = `{
  "publicKey": {
    "rp": {
      "name": "webauthn.io",
      "id": "webauthn.io"
    },
    "user": {
      "id": "nsWi6Nr9u8nAAQ==",
      "name": "emppu",
      "displayName": "emppu"
    },
    "challenge": "7vH6L70QspI4ToHZ6gTJLj74jQ9jj/AzlIQkSlkZX8E=",
    "pubKeyCredParams": [
      {
        "type": "public-key",
        "alg": -7
      }
    ],
    "timeout": 60000,
    "excludeCredentials": [],
    "authenticatorSelection": {
      "residentKey": "discouraged",
      "requireResidentKey": false,
      "userVerification": "discouraged"
    },
    "attestation": "direct",
    "extensions": {
      "credProps": true
    }
  }
}`
