package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/findy-network/findy-grpc/acator"
	"github.com/findy-network/findy-grpc/utils"
	"github.com/golang/glog"
	"github.com/lainio/err2"
)

func main() {
	defer err2.CatchTrace(func(err error) {
		glog.Warningln("")
	})
	err2.Check(startServerCmd.Parse(os.Args[1:]))
	utils.ParseLoggingArgs(loggingFlags)
	//glog.V(3).Infoln("port:", port, "logging:", loggingFlags)

	name := "user100"

	glog.Infoln("Let's start", name)

	r, err := sendAndWaitHTTPRequest("GET", urlStr+"/register/begin/"+name, nil)
	err2.Check(err)
	glog.Infoln("GET send ok, receiving reply")

	defer r.Close()
	ccr, err := acator.Register(r)
	err2.Check(err)
	glog.Infoln("Register json ok handled")

	js, err := json.Marshal(ccr)
	glog.Infoln("POSTing our registering message ")

	r2, err := sendAndWaitHTTPRequest("POST", urlStr+"/register/finish/"+name, bytes.NewReader(js))
	err2.Check(err)
	glog.Infoln("POST sent ok, cot relpy")

	defer r2.Close()
	b := err2.Bytes.Try(ioutil.ReadAll(r2))
	fmt.Println(string(b))
}

var (
	loggingFlags string
	urlStr       string

	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)
)

func init() {
	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2", "logging startup arguments")
	startServerCmd.StringVar(&urlStr, "url", "http://localhost:8080", "web authn server url")
}

func sendAndWaitHTTPRequest(method, addr string, msg io.Reader) (reader io.ReadCloser, err error) {
	defer err2.Annotate("call http", &err)

	c := &http.Client{
		Timeout: 10 * time.Minute,
	}
	URL, err := url.Parse(addr)
	err2.Check(err)

	request, _ := http.NewRequest(method, URL.String(), msg)

	if msg != nil {
		printBodyJSON(request)
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", urlStr)

	response, err := c.Do(request)
	err2.Check(err)

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
