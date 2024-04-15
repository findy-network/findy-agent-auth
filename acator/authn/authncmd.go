// Package authn implements WebAuthn Cmd to Register and Login.
package authn

import (
	"bytes"
	"crypto/tls"
	"encoding/gob"
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
	URL           string `json:"url,omitempty"`
	AAGUID        string `json:"aaguid,omitempty"`
	Key           string `json:"key,omitempty"`
	Counter       uint64 `json:"counter,omitempty"`
	Token         string `json:"token,omitempty"`
	Origin        string `json:"origin,omitempty"`

	RegisterBegin  Endpoint `json:"register_1,omitempty"`
	RegisterFinish Endpoint `json:"register_2,omitempty"`
	LoginBegin     Endpoint `json:"login_1,omitempty"`
	LoginFinish    Endpoint `json:"login_2,omitempty"`

	CookiePath string `json:"cookie_path,omitempty"`
	CookieFile string `json:"cookie_file,omitempty"`

	SecEnclave enclave.Secure `json:"-"`

	Legacy bool `json:"-"`
}

type Endpoint struct {
	Method   string `json:"method,omitempty"`
	Path     string `json:"path,omitempty"`
	Payload  string `json:"payload,omitempty"`
	InPL     string `json:"inputPL,omitempty"`
	MiddlePL string `json:"middlePL,omitempty"`
}

func (ac *Cmd) Validate() (err error) {
	defer err2.Handle(&err)

	assert.NotEmpty(ac.SubCmd, "sub command needed")
	assert.That(ac.SubCmd == "register" || ac.SubCmd == "login",
		"wrong sub command: %s: want: register|login", ac.SubCmd)
	assert.NotEmpty(ac.UserName, "user name needed")
	assert.NotEmpty(ac.URL, "connection url cannot be empty")
	assert.NotEmpty(ac.AAGUID, "authenticator ID needed")
	if ac.Key == "" {
		assert.INotNil(ac.SecEnclave, "secure enclave is needed")
	}

	if ac.Legacy {
		ac.setOldDefaults()
	} else {
		ac.setDefaults()
	}

	if ac.Origin == "" {
		originURL := try.To1(url.Parse(ac.URL))
		ac.Origin = originURL.String()
	}
	return nil
}

func (ac *Cmd) setDefaults() {
	ac.setPayloads()
	ac.setMiddlePayloads()

	if ac.RegisterBegin.Method == "" {
		ac.RegisterBegin.Method = "POST"
	}
	if ac.RegisterFinish.Method == "" {
		ac.RegisterFinish.Method = "POST"
	}
	if ac.LoginBegin.Method == "" {
		ac.LoginBegin.Method = "POST"
	}
	if ac.LoginFinish.Method == "" {
		ac.LoginFinish.Method = "POST"
	}

	if ac.RegisterBegin.Path == "" {
		ac.RegisterBegin.Path = "%s/attestation/options"
	}
	if ac.RegisterFinish.Path == "" {
		ac.RegisterFinish.Path = "%s/attestation/result"
	}
	if ac.LoginBegin.Path == "" {
		ac.LoginBegin.Path = "%s/assertion/options"
	}
	if ac.LoginFinish.Path == "" {
		ac.LoginFinish.Path = "%s/assertion/result"
	}
}

func (ac *Cmd) setMiddlePayloads() {
	if ac.RegisterBegin.MiddlePL == "" {
		ac.RegisterBegin.MiddlePL = `{"publicKey": %s}`
	}
	if ac.LoginBegin.MiddlePL == "" {
		ac.LoginBegin.MiddlePL = `{"publicKey": %s}`
	}
}

// setInPayloads, NOTE: use only for webuathn.io dialect.
func (ac *Cmd) _() {
	if ac.RegisterBegin.InPL == "" {
		ac.RegisterBegin.InPL = `{"username":"%s",
"response": %s }`
	}
	if ac.LoginBegin.InPL == "" {
		ac.LoginBegin.InPL = `{"username":"%s",
"response": %s }`
	}
}

func (ac *Cmd) setPayloads() {
	if ac.RegisterBegin.Payload == "" {
		ac.RegisterBegin.Payload = `{"username":"%s"}`
	}
	if ac.LoginBegin.Payload == "" {
		ac.LoginBegin.Payload = `{"username":"%s"}`
	}
}

func (ac *Cmd) setOldDefaults() {
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

	ec := newExecCmd(ac)
	return *try.To1(execute[cmd](ec)), nil
}

func (ac Cmd) TryReadJSON(r io.Reader) Cmd {
	var newCmd Cmd
	try.To(json.NewDecoder(r).Decode(&newCmd))
	if newCmd.AAGUID == "" {
		newCmd.AAGUID = ac.AAGUID
	}
	if newCmd.URL == "" {
		newCmd.URL = ac.URL
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

type cmdFunc func(ec *execCmd) (*Result, error)

type execCmd struct {
	Cmd
	*acator.Instance

	*http.Client
}

func newExecCmd(cmd *Cmd) (ec *execCmd) {
	assert.NotEmpty(cmd.Origin)
	ec = new(execCmd)
	ec.Cmd = *cmd
	ec.Instance = &acator.Instance{
		Counter: 0,
		AAGUID:  uuid.Must(uuid.Parse("12c85a48-4baf-47bd-b51f-f192871a1511")),
		Origin:  try.To1(url.Parse(cmd.Origin)),
	}
	ec.Client = setupClient()
	return ec
}

var (
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

func empty(*execCmd) (*Result, error) {
	msg := "empty command handler called"
	glog.Warningln(msg)
	return nil, errors.New(msg)
}

func registerUser(ec *execCmd) (result *Result, err error) {
	defer err2.Handle(&err, "register user")

	ec.checkCookiePath()

	var plr io.Reader
	beginURL := fmt.Sprintf(ec.RegisterBegin.Path, ec.URL, ec.UserName, ec.PublicDIDSeed)
	if ec.RegisterBegin.Method == "POST" {
		beginURL = fmt.Sprintf(ec.RegisterBegin.Path, ec.URL)
		glog.V(13).Infoln("us:", beginURL)
		pl := fmt.Sprintf(ec.RegisterBegin.Payload, ec.UserName) //, rpID)
		glog.V(13).Infoln("pl:", pl)
		plr = strings.NewReader(pl)
	}
	r := ec.tryHTTPRequest(ec.RegisterBegin.Method, beginURL, plr)
	defer r.Close()

	var js io.Reader
	if ec.RegisterBegin.MiddlePL != "" {
		glog.V(13).Infoln("==> middle Payload:\n", ec.RegisterBegin.MiddlePL)

		resp := string(try.To1(io.ReadAll(r)))
		pl := fmt.Sprintf(ec.RegisterBegin.MiddlePL, resp)
		glog.V(13).Infoln("middlePL:\n", pl)
		r := strings.NewReader(pl)

		js = try.To1(acator.Register(ec.Instance, r))
	} else {
		js = try.To1(acator.Register(ec.Instance, r))
	}

	glog.V(13).Infoln("Register called")
	if ec.RegisterFinish.Payload != "" {
		glog.V(13).Infoln("==> finish Payload:\n", ec.RegisterFinish.Payload)

		resp := string(try.To1(io.ReadAll(js)))
		fullResp := fmt.Sprintf(ec.RegisterFinish.Payload, ec.UserName, resp)
		glog.V(13).Infoln("fullResp:\n", fullResp)
		js = strings.NewReader(fullResp)
	}

	finishURL := fmt.Sprintf(ec.RegisterFinish.Path, ec.URL)
	if ec.RegisterBegin.Method == "GET" {
		finishURL = fmt.Sprintf(ec.RegisterFinish.Path, ec.URL, ec.UserName)
	}
	r2 := ec.tryHTTPRequest(ec.RegisterFinish.Method, finishURL, js)
	defer r2.Close()

	b := try.To1(io.ReadAll(r2))
	if ec.CookieFile != "" {
		var buf bytes.Buffer
		URL := try.To1(url.Parse(ec.URL))
		cookies := ec.Jar.Cookies(URL)
		try.To(gob.NewEncoder(&buf).Encode(cookies))
		try.To(os.WriteFile(ec.CookieFile, buf.Bytes(), 0664))
		glog.V(3).Infof("saving %d cookies", len(cookies))
	}
	return &Result{SubCmd: "register", Token: string(b)}, nil
}

func loginUser(ec *execCmd) (_ *Result, err error) {
	defer err2.Handle(&err, "login user")

	ec.checkCookiePath()

	var plr io.Reader
	us := fmt.Sprintf(ec.LoginBegin.Path, ec.URL, ec.UserName)
	if ec.LoginBegin.Method == "POST" {
		us = fmt.Sprintf(ec.LoginBegin.Path, ec.URL)
		glog.V(13).Infoln("us:", us)
		pl := fmt.Sprintf(ec.LoginBegin.Payload, ec.UserName) //, rpID)
		glog.V(13).Infoln("pl:", pl)
		plr = strings.NewReader(pl)
	}
	r := ec.tryHTTPRequest(ec.LoginBegin.Method, us, plr)
	defer r.Close()

	var js io.Reader
	if ec.LoginBegin.MiddlePL != "" {
		glog.V(13).Infoln("==> middle Payload:\n", ec.LoginBegin.MiddlePL)

		resp := string(try.To1(io.ReadAll(r)))
		pl := fmt.Sprintf(ec.LoginBegin.MiddlePL, resp)
		glog.V(13).Infoln("middlePL:\n", pl)
		r := strings.NewReader(pl)
		js = try.To1(acator.Login(ec.Instance, r))
	} else {
		js = try.To1(acator.Login(ec.Instance, r))
	}
	if ec.LoginFinish.Payload != "" {
		glog.V(13).Infoln("==> finish Payload:\n", ec.LoginFinish.Payload)

		resp := string(try.To1(io.ReadAll(js)))
		fullResp := fmt.Sprintf(ec.LoginFinish.Payload, ec.UserName, resp)
		glog.V(13).Infoln("fullResp:\n", fullResp)
		js = strings.NewReader(fullResp)
	}

	finishURL := fmt.Sprintf(ec.LoginFinish.Path, ec.URL)
	if ec.LoginBegin.Method == "GET" {
		finishURL = fmt.Sprintf(ec.LoginFinish.Path, ec.URL, ec.UserName)
	}

	r2 := ec.tryHTTPRequest(ec.LoginFinish.Method, finishURL, js)
	defer r2.Close()

	var result Result
	if ec.LoginBegin.Method == "GET" {
		try.To(json.NewDecoder(r2).Decode(&result))
	} else {
		b := try.To1(io.ReadAll(r2))
		result.Token = string(b)
	}
	result.SubCmd = "login"
	return &result, nil
}

func (ec *execCmd) tryHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser) {
	glog.V(13).Infof("=== '%v'", addr)
	URL := try.To1(url.Parse(addr))
	request, _ := http.NewRequest(method, URL.String(), msg)

	echoReqToStdout(request)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", ec.Instance.Origin.String())
	request.Header.Add("Accept", "*/*")
	// if we want to register a new authenticator, we must send valid JWT
	if ec.Token != "" {
		request.Header.Add("Authorization", "Bearer "+ec.Token)
	}
	if rawCookies := os.Getenv("COOKIE"); rawCookies != "" {
		glog.V(3).Infoln("setting cookies from env (COOKIE):\n", rawCookies)
		request.Header.Add("Cookie", rawCookies)
	}
	response := try.To1(ec.Do(request)) //nolint: bodyclose

	cookies := response.Cookies()
	glog.V(3).Infof("getting %d cookies from response", len(cookies))
	ec.addToCookieJar(URL, cookies)

	if response.StatusCode == http.StatusInternalServerError {
		d := string(try.To1(io.ReadAll(response.Body)))
		glog.Errorln("Server error:", d)
		err2.Throwf("SERVER error: %v", d)
	} else if response.StatusCode == http.StatusBadRequest {
		d := string(try.To1(io.ReadAll(response.Body)))
		glog.Errorln("BAD Request:", d)
		err2.Throwf("error bad: %v", d)
	} else if response.StatusCode != http.StatusOK {
		err2.Throwf("status code: %v", response.Status)
	}

	echoRespToStdout(response)

	return response.Body
}

func (ec *execCmd) addToCookieJar(URL *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		glog.V(3).Infoln("--- adding cookie:", c.String())
	}
	jarCookies := ec.Jar.Cookies(URL)
	cookies = append(cookies, jarCookies...)
	glog.V(3).Infof("jar cookie len %d, response cookie len: %d",
		len(jarCookies), len(cookies))
	ec.Jar.SetCookies(URL, cookies)
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

func (ec *execCmd) checkCookiePath() {
	if ec.CookieFile != "" && ec.CookiePath == "" {
		data := try.To1(os.ReadFile(ec.CookieFile))
		buf := bytes.NewReader(data)
		URL := try.To1(url.Parse(ec.URL))
		var cookies []*http.Cookie
		try.To(gob.NewDecoder(buf).Decode(&cookies))
		glog.V(3).Infof("loading %d cookies", len(cookies))
		ec.Jar.SetCookies(URL, cookies)
	} else if ec.CookiePath != "" { // just load page
		// assert.NotEmpty(cookieFile)
		// make the http request to load the page AND cookies
		glog.V(3).Infof("cookie path: '%s'", ec.CookiePath)
		if ec.CookiePath == "-" {
			ec.CookiePath = ""
		}
		cookiePageURL := ec.URL + ec.CookiePath
		glog.V(3).Infoln("loading cookie page:", cookiePageURL)
		r := ec.tryHTTPRequest("GET", cookiePageURL, &bytes.Buffer{})
		// we don't know how the server behaves, we don't want it to abort
		_ = try.To1(io.ReadAll(r))
	}
}
