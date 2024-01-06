package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var userCfg = userInfo{
	Username:         "test-user",
	DisplayName:      "Test Number One",
	UserVerification: "",
	Seed:             "",
}

func TestRegisterBegin(t *testing.T) {
	defer assert.PushTester(t)()

	sendPL := try.To1(json.Marshal(userCfg))
	req := httptest.NewRequest(http.MethodGet, urlBeginRegister,
		bytes.NewReader(sendPL))
	w := httptest.NewRecorder()

	BeginRegistration(w, req)

	res := w.Result()
	defer res.Body.Close()
	data := try.To1(io.ReadAll(res.Body))
	//want := `{"rp":{"name":"Findy Agency","id":"http://localhost"},"user":{"name":"test-user","displayName":"test-user","id":"wbXI2OaJrKaAAQ"},"challenge":"qCzrcuGEVcSeXiT75HhdTiOfjwWGwa5iCkj1ibq5fDk","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-35},{"type":"public-key","alg":-36},{"type":"public-key","alg":-257},{"type":"public-key","alg":-258},{"type":"public-key","alg":-259},{"type":"public-key","alg":-37},{"type":"public-key","alg":-38},{"type":"public-key","alg":-39},{"type":"public-key","alg":-8}],"timeout":300000,"authenticatorSelection":{"requireResidentKey":false,"userVerification":"preferred"}}`
	assert.Equal(res.StatusCode, http.StatusOK)
	assert.That(len(data) > 0)
	//assert.Equal(string(data), want)

	// TODO: continue with client logic!
}

func TestRegisterFinish(t *testing.T) {
	defer assert.PushTester(t)()

	sendPL := try.To1(json.Marshal(userCfg))
	req := httptest.NewRequest(http.MethodGet, urlBeginRegister,
		bytes.NewReader(sendPL))
	w := httptest.NewRecorder()

	FinishRegistration(w, req)

	res := w.Result()
	defer res.Body.Close()
	data := try.To1(io.ReadAll(res.Body))
	want := ""
	assert.Equal(string(data), want)
	assert.Equal(res.StatusCode, http.StatusOK)
}

func TestLoginBegin(t *testing.T) {
	defer assert.PushTester(t)()

	sendPL := try.To1(json.Marshal(userCfg))
	req := httptest.NewRequest(http.MethodGet, urlBeginLogin,
		bytes.NewReader(sendPL))
	w := httptest.NewRecorder()

	BeginLogin(w, req)

	res := w.Result()
	defer res.Body.Close()
	data := try.To1(io.ReadAll(res.Body))
	want := "1"
	assert.Equal(string(data), want)
	assert.Equal(res.StatusCode, http.StatusOK)
}

func TestLoginFinish(t *testing.T) {
	defer assert.PushTester(t)()

	sendPL := try.To1(json.Marshal(userCfg))
	req := httptest.NewRequest(http.MethodGet, urlBeginLogin,
		bytes.NewReader(sendPL))
	w := httptest.NewRecorder()

	FinishLogin(w, req)

	res := w.Result()
	defer res.Body.Close()
	data := try.To1(io.ReadAll(res.Body))
	want := ""
	assert.Equal(string(data), want)
	assert.Equal(res.StatusCode, http.StatusOK)
}

func TestMain(m *testing.M) {
	try.To(flag.Set("logtostderr", "true"))
	try.To(flag.Set("v", "0"))
	setUp()
	code := m.Run()
	tearDown()
	os.Exit(code)
}

func setUp() {
	enclaveFile = "MEMORY_enc.bolt"
	enclaveBackup = ""
	enclaveKey = ""
	//sessionStore = try.To1(session.NewStore())
	setupEnv()
}

func tearDown() {}
