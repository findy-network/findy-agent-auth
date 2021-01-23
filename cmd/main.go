package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"

	"github.com/findy-network/findy-grpc/acator"
	"github.com/findy-network/findy-grpc/utils"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"golang.org/x/net/publicsuffix"
)

func main() {
	defer err2.CatchTrace(func(err error) {
		glog.Warningln("")
	})
	err2.Check(startServerCmd.Parse(os.Args[1:]))
	utils.ParseLoggingArgs(loggingFlags)
	//glog.V(3).Infoln("port:", port, "logging:", loggingFlags)

	if len(startServerCmd.Args()) != 2 || processArgs(startServerCmd.Args()) != nil {
		println("usage:\tauthn <register|login> <reg-name>")
		return
	}

	err2.Check(cmdFuncs[cmd]())
}

func empty() error {
	glog.Warningln("empty command handler called")
	return nil
}

func registerUser() (err error) {
	defer err2.Annotate("register user", &err)

	glog.Infoln("Let's start REGISTER", name)

	r, err := sendAndWaitHTTPRequest("GET", urlStr+"/register/begin/"+name, nil)
	err2.Check(err)
	glog.Infoln("GET send ok, receiving reply")

	defer r.Close()
	ccr, err := acator.Register(r)
	err2.Check(err)
	glog.Infoln("Register json handled OK")

	js, err := json.Marshal(ccr)
	glog.Infoln("POSTing our registering message ")

	r2, err := sendAndWaitHTTPRequest("POST", urlStr+"/register/finish/"+name, bytes.NewReader(js))
	err2.Check(err)
	glog.Infoln("POST sent ok, got reply")

	defer r2.Close()
	b := err2.Bytes.Try(ioutil.ReadAll(r2))
	fmt.Println(string(b))

	return nil
}

func loginUser() (err error) {
	defer err2.Annotate("login user", &err)

	glog.Infoln("Let's start LOGIN", name)

	r, err := sendAndWaitHTTPRequest("GET", urlStr+"/login/begin/"+name, nil)
	err2.Check(err)
	glog.Infoln("GET send ok, receiving Login challenge")

	defer r.Close()
	assertionResponse, err := acator.Login(r)
	err2.Check(err)
	glog.Infoln("Login json handled OK")

	js, err := json.Marshal(assertionResponse)

	glog.Infoln("POSTing our login message ")
	r2, err := sendAndWaitHTTPRequest("POST", urlStr+"/login/finish/"+name, bytes.NewReader(js))
	err2.Check(err)
	glog.Infoln("POST sent ok, got reply")

	defer r2.Close()
	b := err2.Bytes.Try(ioutil.ReadAll(r2))
	fmt.Println(string(b))

	return nil
}

func processArgs(args []string) (err error) {
	cmd = cmdModes[args[0]]
	if cmd == 0 {
		return fmt.Errorf("wrong command")
	}
	name = args[1]
	return nil
}

type cmdMode int

const (
	register cmdMode = iota + 1
	login
)

type cmdFunc func() error

var (
	cmd          cmdMode
	name         string
	loggingFlags string
	urlStr       string

	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)

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

func init() {
	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2", "logging startup arguments")
	startServerCmd.StringVar(&urlStr, "url", "http://localhost:8090", "web authn server url")
}

func sendAndWaitHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser, err error) {
	defer err2.Annotate("call http", &err)

	URL, err := url.Parse(addr)
	err2.Check(err)

	request, _ := http.NewRequest(method, URL.String(), msg)

	if msg != nil {
		printBodyJSON(request)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", urlStr)
	request.Header.Add("Accept", "*/*")
	request.Header.Add("Cookie", "kviwkdmc83en9csd893j2d298jd8u2c3jd283jcdn2cwc937jd97823jc73h2d67g9d236ch2")

	response, err := c.Do(request)
	err2.Check(err)

	c.Jar.SetCookies(URL, response.Cookies())

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %v", response.Status)
	}
	responseBodyJSON(response)
	return response.Body, nil
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
