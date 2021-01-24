package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/findy-network/findy-grpc/acator/authn"
	"github.com/findy-network/findy-grpc/utils"
	"github.com/golang/glog"
	"github.com/lainio/err2"
)

func main() {
	defer err2.CatchTrace(func(err error) {
		glog.Warningln(err)
	})
	err2.Check(startServerCmd.Parse(os.Args[1:]))
	utils.ParseLoggingArgs(loggingFlags)
	//glog.V(3).Infoln("port:", port, "logging:", loggingFlags)

	if len(startServerCmd.Args()) != 2 || processArgs(startServerCmd.Args()) != nil {
		println("usage:\tauthn <register|login> <reg-name>")
		return
	}

	ac := authn.Cmd{
		SubCmd:   startServerCmd.Arg(0),
		UserName: name,
		Url:      urlStr,
		AAGUID:   "12c85a48-4baf-47bd-b51f-f192871a1511", // read from some where!!
		Key:      "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c",
		Counter:  3, // read from some where!!
	}
	r, err := ac.Exec(os.Stdout)
	err2.Check(err)
	println(r.String())

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

	cmdModes = map[string]cmdMode{
		"register": register,
		"login":    login,
	}
)

func init() {
	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2", "logging startup arguments")
	startServerCmd.StringVar(&urlStr, "url", "http://localhost:8090", "web authn server url")
}
