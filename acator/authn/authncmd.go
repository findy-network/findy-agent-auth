// Package authn implements WebAuthn Cmd to Register and Login.
package authn

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/findy-network/findy-agent-auth/acator"
	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"

	"github.com/lainio/err2/assert"
	"golang.org/x/net/publicsuffix"
)

type Cmd struct {
	SubCmd        string `json:"sub_cmd"`
	UserName      string `json:"user_name"`
	PublicDIDSeed string `json:"public_did_seed"`
	Url           string `json:"url,omitempty"`
	RPID          string `json:"rpid,omitempty"`
	AAGUID        string `json:"aaguid,omitempty"`
	Key           string `json:"key,omitempty"`
	Counter       uint64 `json:"counter,omitempty"`
	Token         string `json:"token,omitempty"`
	Origin        string `json:"origin,omitempty"`

	RegisterBegin  Endpoint `json:"register_1,omitempty"`
	RegisterFinish Endpoint `json:"register_2,omitempty"`
	LoginBegin     Endpoint `json:"login_1,omitempty"`
	LoginFinish    Endpoint `json:"login_2,omitempty"`

	SecEnclave enclave.Secure `json:"-"`
}

type Endpoint struct {
	Method  string `json:"method,omitempty"`
	Path    string `json:"path,omitempty"`
	Payload string `json:"payload,omitempty"`
}

func (ac *Cmd) Validate() (err error) {
	defer err2.Handle(&err)

	assert.NotEmpty(ac.SubCmd, "sub command needed")
	assert.That(ac.SubCmd == "register" || ac.SubCmd == "login",
		"wrong sub command: %s: want: register|login", ac.SubCmd)
	assert.NotEmpty(ac.UserName, "user name needed")
	assert.NotEmpty(ac.Url, "connection url cannot be empty")
	assert.NotEmpty(ac.AAGUID, "authenticator ID needed")
	if ac.Key == "" {
		assert.INotNil(ac.SecEnclave, "secure enclave is needed")
	}

	if ac.RegisterBegin.Method == "" {
		ac.RegisterBegin.Method = "GET"
	}
	if ac.RegisterFinish.Method == "" {
		ac.RegisterFinish.Method = "POST"
	}
	if ac.LoginBegin.Method == "" {
		ac.LoginBegin.Method = "GET"
	}
	if ac.LoginFinish.Method == "" {
		ac.LoginFinish.Method = "POST"
	}

	if ac.RegisterBegin.Path == "" {
		ac.RegisterBegin.Path = "%s/register/begin/%s?seed=%s"
	}
	if ac.RegisterFinish.Path == "" {
		ac.RegisterFinish.Path = "%s/register/finish/%s"
	}
	if ac.LoginBegin.Path == "" {
		ac.LoginBegin.Path = "%s/login/begin/%s"
	}
	if ac.LoginFinish.Path == "" {
		ac.LoginFinish.Path = "%s/login/finish/%s"
	}

	return nil
}

type Result struct {
	SubCmd string `json:"sub_cmd,omitempty"`
	Token  string `json:"token"`
}

func (r Result) String() string {
	d, _ := json.Marshal(r)
	return string(d)
}

func (ac *Cmd) Exec(_ io.Writer) (r Result, err error) {
	defer err2.Handle(&err, "execute authenticator")

	try.To(ac.Validate())

	if ac.SecEnclave != nil {
		glog.V(3).Infoln("------ using callers secure enclave")
		enclave.Store = ac.SecEnclave
	} else {
		glog.V(5).Infoln("using master key, no secure enclave")
		assert.NotEmpty(ac.Key) // just make sure
		enclave.Store = enclave.New(ac.Key)
	}

	cmd := cmdModes[ac.SubCmd]

	acator.AAGUID = uuid.Must(uuid.Parse(ac.AAGUID))
	acator.Counter = uint32(ac.Counter)
	name = ac.UserName
	seed = ac.PublicDIDSeed
	urlStr = ac.Url
	loginBegin, loginFinish, registerBegin, registerFinish =
		ac.LoginBegin, ac.LoginFinish, ac.RegisterBegin, ac.RegisterFinish
	glog.V(13).Infof("json B: %v", registerBegin)
	glog.V(13).Infof("json F: %v", registerFinish)
	//rpID = ac.RPID
	if ac.Origin != "" {
		origin = ac.Origin
		originURL := try.To1(url.Parse(ac.Origin))
		acator.Origin = *originURL
	} else {
		origin = ac.Url
		originURL := try.To1(url.Parse(urlStr))
		acator.Origin = *originURL
	}
	jwtToken = ac.Token

	return *try.To1(execute[cmd]()), nil
}

func (ac Cmd) TryReadJSON(r io.Reader) Cmd {
	var newCmd Cmd
	try.To(json.NewDecoder(r).Decode(&newCmd))
	if newCmd.AAGUID == "" {
		newCmd.AAGUID = ac.AAGUID
	}
	if newCmd.Url == "" {
		newCmd.Url = ac.Url
	}
	if newCmd.Key == "" {
		newCmd.Key = ac.Key
	}
	if newCmd.Counter == 0 {
		newCmd.Counter = ac.Counter
	}
	return newCmd
}

type cmdMode int

const (
	register cmdMode = iota + 1
	login
)

type cmdFunc func() (*Result, error)

var (
	//rpID     string
	name     string
	seed     string
	urlStr   string
	origin   string
	jwtToken string

	// format strings to build actual endpoints
	loginBegin, loginFinish, registerBegin, registerFinish Endpoint

	c = setupClient()

	cmdModes = map[string]cmdMode{
		"register": register,
		"login":    login,
	}

	execute = []cmdFunc{
		empty,
		registerUser,
		loginUser,
	}
)

func empty() (*Result, error) {
	msg := "empty command handler called"
	glog.Warningln(msg)
	return nil, errors.New(msg)
}

func registerUser() (result *Result, err error) {
	defer err2.Handle(&err, "register user")

	var plr io.Reader
	beginURL := fmt.Sprintf(registerBegin.Path, urlStr, name, seed)
	if registerBegin.Method == "POST" {
		beginURL = fmt.Sprintf(registerBegin.Path, urlStr)
		glog.V(13).Infoln("us:", beginURL)
		pl := fmt.Sprintf(registerBegin.Payload, name) //, rpID)
		glog.V(13).Infoln("pl:", pl)
		plr = strings.NewReader(pl)
	}
	r := tryHTTPRequest(registerBegin.Method, beginURL, plr)
	defer r.Close()

	js := try.To1(acator.Register(r))
	glog.V(13).Infoln("Register called")
	if registerFinish.Payload != "" {
		glog.V(13).Infoln("==> finish Payload:\n", registerFinish.Payload)

		resp := string(try.To1(io.ReadAll(js)))
		fullResp := fmt.Sprintf(registerFinish.Payload, name, resp)
		glog.V(13).Infoln("fullResp:\n", fullResp)
		js = strings.NewReader(fullResp)
	}

	finishURL := fmt.Sprintf(registerFinish.Path, urlStr)
	if registerBegin.Method == "GET" {
		finishURL = fmt.Sprintf(registerFinish.Path, urlStr, name)
	}
	r2 := tryHTTPRequest(registerFinish.Method, finishURL, js)
	defer r2.Close()

	b := try.To1(io.ReadAll(r2))
	return &Result{SubCmd: "register", Token: string(b)}, nil
}

func loginUser() (_ *Result, err error) {
	defer err2.Handle(&err, "login user")

	var plr io.Reader
	us := fmt.Sprintf(loginBegin.Path, urlStr, name)
	if loginBegin.Method == "POST" {
		us = fmt.Sprintf(loginBegin.Path, urlStr)
		glog.V(13).Infoln("us:", us)
		pl := fmt.Sprintf(loginBegin.Payload, name) //, rpID)
		glog.V(13).Infoln("pl:", pl)
		plr = strings.NewReader(pl)
	}
	r := tryHTTPRequest(loginBegin.Method, us, plr)
	defer r.Close()

	js := try.To1(acator.Login(r))

	r2 := tryHTTPRequest(loginFinish.Method, fmt.Sprintf(loginFinish.Path, urlStr, name), js)
	defer r2.Close()

	var result Result
	try.To(json.NewDecoder(r2).Decode(&result))

	result.SubCmd = "login"
	return &result, nil
}

func tryHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser) {
	glog.V(13).Infoln("===", addr)
	URL := try.To1(url.Parse(addr))
	request, _ := http.NewRequest(method, URL.String(), msg)

	echoReqToStdout(request)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", origin)
	request.Header.Add("Accept", "*/*")
	// if we want to register a new authenticator, we must send valid JWT
	if jwtToken != "" {
		request.Header.Add("Authorization", "Bearer "+jwtToken)
	}

	response := try.To1(c.Do(request))

	c.Jar.SetCookies(URL, response.Cookies())

	if response.StatusCode == http.StatusBadRequest {
		d := string(try.To1(io.ReadAll(response.Body)))
		glog.Errorln("BAD:", d)
		err2.Throwf("error bad: %v", d)
	} else if response.StatusCode != http.StatusOK {
		err2.Throwf("status code: %v", response.Status)
	}

	echoRespToStdout(response)

	return response.Body
}

func setupClient() (client *http.Client) {
	options := cookiejar.Options{
		// All users of cookiejar should import "golang.org/x/net/publicsuffix"
		PublicSuffixList: publicsuffix.List,
	}

	jar := try.To1(cookiejar.New(&options))

	// allow self generated TLS certificate TODO check this later
	tx := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client = &http.Client{
		Jar:       jar,
		Timeout:   time.Minute * 10,
		Transport: tx,
	}
	return
}

func echoReqToStdout(r *http.Request) {
	if glog.V(5) && r.Body != nil {
		r.Body = &struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, os.Stdout), r.Body}
	}
}

func echoRespToStdout(r *http.Response) {
	if glog.V(5) && r.Body != nil {
		r.Body = &struct {
			io.Reader
			io.Closer
		}{io.TeeReader(r.Body, os.Stdout), r.Body}
	}
}
