package authn

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"github.com/findy-network/findy-grpc/acator"
	"github.com/findy-network/findy-grpc/acator/cose"
	"github.com/golang/glog"
	"github.com/google/uuid"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"golang.org/x/net/publicsuffix"
)

type Cmd struct {
	SubCmd   string `json:"sub_cmd"`
	UserName string `json:"user_name"`
	Url      string `json:"url"`
	AAGUID   string `json:"aaguid"`
	Key      string `json:"key"`
	Counter  uint32 `json:"counter"`
}

func (ac *Cmd) Validate() (err error) {
	assert.ProductionMode = true
	defer err2.Return(&err)

	assert.NotEmpty(ac.SubCmd, "sub command needed")
	assert.Truef(ac.SubCmd == "register" || ac.SubCmd == "login",
		"wrong sub command: %s: want: register|login", ac.SubCmd)
	assert.NotEmpty(ac.UserName, "user name needed")
	assert.NotEmpty(ac.Url, "connection url cannot be empty")
	assert.NotEmpty(ac.AAGUID, "authenticator ID needed")
	assert.NotEmpty(ac.Key, "master key needed")

	return nil
}

type Result struct {
	Token string `json:"token"`
}

func (r Result) String() string {
	d, _ := json.Marshal(r)
	return string(d)
}

func (ac *Cmd) Exec(_ io.Writer) (r Result, err error) {
	defer err2.Annotate("authn cmd exec", &err)

	err2.Check(ac.Validate())

	err2.Check(cose.SetMasterKey(ac.Key))
	cmd := cmdModes[ac.SubCmd]
	acator.AAGUID = uuid.Must(uuid.Parse(ac.AAGUID))
	acator.Counter = ac.Counter
	name = ac.UserName
	urlStr = ac.Url
	originURL, err := url.Parse(urlStr)
	err2.Check(err)
	acator.Origin = *originURL

	result, err := cmdFuncs[cmd]()
	err2.Check(err)

	return *result, nil
}

type cmdMode int

const (
	register cmdMode = iota + 1
	login
)

type cmdFunc func() (*Result, error)

var (
	name   string
	urlStr string

	c = setupClient()

	cmdModes = map[string]cmdMode{
		"register": register,
		"login":    login,
	}

	cmdFuncs = []cmdFunc{
		empty,
		registerUser,
		loginUser,
	}
)

func empty() (*Result, error) {
	glog.Warningln("empty command handler called")
	return nil, nil
}

func registerUser() (result *Result, err error) {
	defer err2.Annotate("register user", &err)

	glog.Infoln("Let's start REGISTER", name)

	r := trySendAndWaitHTTPRequest("GET", urlStr+"/register/begin/"+name, nil)
	glog.Infoln("GET send ok, receiving reply")

	defer r.Close()
	js := err2.R.Try(acator.Register(r))
	glog.Infoln("Register json handled OK")

	glog.Infoln("POSTing our registering message ")
	r2 := trySendAndWaitHTTPRequest("POST", urlStr+"/register/finish/"+name, js)
	glog.Infoln("POST sent ok, got reply")

	defer r2.Close()
	b := err2.Bytes.Try(ioutil.ReadAll(r2))
	fmt.Println(string(b))

	return &Result{Token: string(b)}, nil
}

func loginUser() (_ *Result, err error) {
	defer err2.Annotate("login user", &err)

	glog.Infoln("Let's start LOGIN", name)

	r := trySendAndWaitHTTPRequest("GET", urlStr+"/login/begin/"+name, nil)
	glog.Infoln("GET send ok, receiving Login challenge")

	defer r.Close()
	js := err2.R.Try(acator.Login(r))
	glog.Infoln("Login json handled OK")

	glog.Infoln("POSTing our login message ")
	r2 := trySendAndWaitHTTPRequest("POST", urlStr+"/login/finish/"+name, js)
	glog.Infoln("POST sent ok, got reply")

	defer r2.Close()

	var result Result
	err2.Check(json.NewDecoder(r2).Decode(&result))

	return &result, nil
}

func trySendAndWaitHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser) {
	URL := err2.URL.Try(url.Parse(addr))
	request, _ := http.NewRequest(method, URL.String(), msg)

	if msg != nil {
		printBodyJSON(request)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", urlStr)
	request.Header.Add("Accept", "*/*")
	request.Header.Add("Cookie", "kviwkdmc83en9csd893j2d298jd8u2c3jd283jcdn2cwc937jd97823jc73h2d67g9d236ch2")

	response := err2.Response.Try(c.Do(request))

	c.Jar.SetCookies(URL, response.Cookies())

	if response.StatusCode != http.StatusOK {
		err2.Check(fmt.Errorf("status code: %v", response.Status))
	}
	responseBodyJSON(response)
	return response.Body
}

func setupClient() (client *http.Client) {
	println("client setup")

	// Set cookiejar options
	options := cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	// Create new cookiejar for holding cookies
	jar, _ := cookiejar.New(&options)

	// Create new http client with predefined options
	client = &http.Client{
		Jar:     jar,
		Timeout: time.Minute * 10,
	}
	return
}

func printBodyJSON(r *http.Request) {
	r.Body = &struct {
		io.Reader
		io.Closer
	}{io.TeeReader(r.Body, os.Stdout), r.Body}
}

func responseBodyJSON(r *http.Response) {
	r.Body = &struct {
		io.Reader
		io.Closer
	}{io.TeeReader(r.Body, os.Stdout), r.Body}
}
