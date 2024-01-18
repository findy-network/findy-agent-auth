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
	UserName = ac.UserName
	PublicDIDSeed = ac.PublicDIDSeed
	URL = ac.URL
	LoginBegin, LoginFinish, RegisterBegin, RegisterFinish =
		ac.LoginBegin, ac.LoginFinish, ac.RegisterBegin, ac.RegisterFinish
	CookieFile = ac.CookieFile
	CookiePath = ac.CookiePath
	glog.V(13).Infof("json B: %v", LoginBegin)
	glog.V(13).Infof("json B: %v", LoginBegin)
	glog.V(13).Infof("json F: %v", LoginFinish)
	if ac.Origin != "" {
		Origin = ac.Origin
		originURL := try.To1(url.Parse(ac.Origin))
		acator.Origin = *originURL
	} else {
		Origin = ac.URL
		originURL := try.To1(url.Parse(URL))
		acator.Origin = *originURL
	}
	Token = ac.Token

	// TODO: grpcenclave needs fully stateless system. We need to check the
	// others as well. This was causing problems. It seems that this there is a
	// lot of pkg level variables. All of them have to move!!!
	if c != nil {
		glog.V(3).Info("resetting cookie jar")
		j := try.To1(cookiejar.New(nil))
		c.Jar = j
	}
	return *try.To1(execute[cmd]()), nil
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

type cmdFunc func() (*Result, error)

type execCmd struct {
	Cmd

	//c = setupClient()
	c *http.Client
}

func newExecCmd(cmd *Cmd) *execCmd {
	ec := new(execCmd)
	ec.Cmd = *cmd
	ec.c = setupClient()
	return ec
}

var (
	CookiePath, CookieFile string

	UserName      string
	PublicDIDSeed string
	URL           string
	Origin        string
	Token         string

	// format strings to build actual endpoints
	LoginBegin, LoginFinish, RegisterBegin, RegisterFinish Endpoint

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

	checkCookiePath()

	var plr io.Reader
	beginURL := fmt.Sprintf(RegisterBegin.Path, URL, UserName, PublicDIDSeed)
	if RegisterBegin.Method == "POST" {
		beginURL = fmt.Sprintf(RegisterBegin.Path, URL)
		glog.V(13).Infoln("us:", beginURL)
		pl := fmt.Sprintf(RegisterBegin.Payload, UserName) //, rpID)
		glog.V(13).Infoln("pl:", pl)
		plr = strings.NewReader(pl)
	}
	r := tryHTTPRequest(RegisterBegin.Method, beginURL, plr)
	defer r.Close()

	var js io.Reader
	if RegisterBegin.MiddlePL != "" {
		glog.V(13).Infoln("==> middle Payload:\n", RegisterBegin.MiddlePL)

		resp := string(try.To1(io.ReadAll(r)))
		pl := fmt.Sprintf(RegisterBegin.MiddlePL, resp)
		glog.V(13).Infoln("middlePL:\n", pl)
		r := strings.NewReader(pl)

		js = try.To1(acator.Register(r))
	} else {
		js = try.To1(acator.Register(r))
	}

	glog.V(13).Infoln("Register called")
	if RegisterFinish.Payload != "" {
		glog.V(13).Infoln("==> finish Payload:\n", RegisterFinish.Payload)

		resp := string(try.To1(io.ReadAll(js)))
		fullResp := fmt.Sprintf(RegisterFinish.Payload, UserName, resp)
		glog.V(13).Infoln("fullResp:\n", fullResp)
		js = strings.NewReader(fullResp)
	}

	finishURL := fmt.Sprintf(RegisterFinish.Path, URL)
	if RegisterBegin.Method == "GET" {
		finishURL = fmt.Sprintf(RegisterFinish.Path, URL, UserName)
	}
	r2 := tryHTTPRequest(RegisterFinish.Method, finishURL, js)
	defer r2.Close()

	b := try.To1(io.ReadAll(r2))
	if CookieFile != "" {
		var buf bytes.Buffer
		URL := try.To1(url.Parse(URL))
		cookies := c.Jar.Cookies(URL)
		try.To(gob.NewEncoder(&buf).Encode(cookies))
		try.To(os.WriteFile(CookieFile, buf.Bytes(), 0664))
		glog.V(3).Infof("saving %d cookies", len(cookies))
	}
	return &Result{SubCmd: "register", Token: string(b)}, nil
}

func loginUser() (_ *Result, err error) {
	defer err2.Handle(&err, "login user")

	checkCookiePath()

	var plr io.Reader
	us := fmt.Sprintf(LoginBegin.Path, URL, UserName)
	if LoginBegin.Method == "POST" {
		us = fmt.Sprintf(LoginBegin.Path, URL)
		glog.V(13).Infoln("us:", us)
		pl := fmt.Sprintf(LoginBegin.Payload, UserName) //, rpID)
		glog.V(13).Infoln("pl:", pl)
		plr = strings.NewReader(pl)
	}
	r := tryHTTPRequest(LoginBegin.Method, us, plr)
	defer r.Close()

	var js io.Reader
	if LoginBegin.MiddlePL != "" {
		glog.V(13).Infoln("==> middle Payload:\n", LoginBegin.MiddlePL)

		resp := string(try.To1(io.ReadAll(r)))
		pl := fmt.Sprintf(LoginBegin.MiddlePL, resp)
		glog.V(13).Infoln("middlePL:\n", pl)
		r := strings.NewReader(pl)
		js = try.To1(acator.Login(r))
	} else {
		js = try.To1(acator.Login(r))
	}
	if LoginFinish.Payload != "" {
		glog.V(13).Infoln("==> finish Payload:\n", LoginFinish.Payload)

		resp := string(try.To1(io.ReadAll(js)))
		fullResp := fmt.Sprintf(LoginFinish.Payload, UserName, resp)
		glog.V(13).Infoln("fullResp:\n", fullResp)
		js = strings.NewReader(fullResp)
	}

	finishURL := fmt.Sprintf(LoginFinish.Path, URL)
	if LoginBegin.Method == "GET" {
		finishURL = fmt.Sprintf(LoginFinish.Path, URL, UserName)
	}

	r2 := tryHTTPRequest(LoginFinish.Method, finishURL, js)
	defer r2.Close()

	var result Result
	if LoginBegin.Method == "GET" {
		try.To(json.NewDecoder(r2).Decode(&result))
	} else {
		b := try.To1(io.ReadAll(r2))
		result.Token = string(b)
	}
	result.SubCmd = "login"
	return &result, nil
}

func tryHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser) {
	glog.V(13).Infoln("===", addr)
	URL := try.To1(url.Parse(addr))
	request, _ := http.NewRequest(method, URL.String(), msg)

	echoReqToStdout(request)

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", Origin)
	request.Header.Add("Accept", "*/*")
	// if we want to register a new authenticator, we must send valid JWT
	if Token != "" {
		request.Header.Add("Authorization", "Bearer "+Token)
	}
	if rawCookies := os.Getenv("COOKIE"); rawCookies != "" {
		glog.V(3).Infoln("setting cookies from env (COOKIE):\n", rawCookies)
		request.Header.Add("Cookie", rawCookies)
	}
	response := try.To1(c.Do(request)) //nolint: bodyclose

	cookies := response.Cookies()
	glog.V(3).Infof("getting %d cookies from response", len(cookies))
	addToCookieJar(URL, cookies)

	if response.StatusCode == http.StatusInternalServerError {
		d := string(try.To1(io.ReadAll(response.Body)))
		glog.Errorln("Server error:", d)
		err2.Throwf("SERVER error: %v", d)
	} else if response.StatusCode == http.StatusBadRequest {
		d := string(try.To1(io.ReadAll(response.Body)))
		glog.Errorln("BAD:", d)
		err2.Throwf("error bad: %v", d)
	} else if response.StatusCode != http.StatusOK {
		err2.Throwf("status code: %v", response.Status)
	}

	echoRespToStdout(response)

	return response.Body
}

func addToCookieJar(URL *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		glog.V(1).Infoln("--- adding cookie:", c.String())
	}
	jarCookies := c.Jar.Cookies(URL)
	cookies = append(cookies, jarCookies...)
	glog.V(3).Infof("jar cookie len %d, response cookie len: %d",
		len(jarCookies), len(cookies))
	c.Jar.SetCookies(URL, cookies)
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

func checkCookiePath() {
	if CookieFile != "" && CookiePath == "" {
		data := try.To1(os.ReadFile(CookieFile))
		buf := bytes.NewReader(data)
		URL := try.To1(url.Parse(URL))
		var cookies []*http.Cookie
		try.To(gob.NewDecoder(buf).Decode(&cookies))
		glog.V(3).Infof("loading %d cookies", len(cookies))
		c.Jar.SetCookies(URL, cookies)
	} else if CookiePath != "" { // just load page
		// assert.NotEmpty(cookieFile)
		// make the http request to load the page AND cookies
		glog.V(1).Infof("cookie path: '%s'", CookiePath)
		if CookiePath == "-" {
			CookiePath = ""
		}
		cookiePageURL := URL + CookiePath
		glog.V(1).Infoln("loading cookie page:", cookiePageURL)
		r := tryHTTPRequest("GET", cookiePageURL, &bytes.Buffer{})
		// we don't know how the server behaves, we don't want it to abort
		_ = try.To1(io.ReadAll(r))
	}
}
