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

	r, err := authnCmd.Exec(os.Stdout)
	err2.Check(err)
	fmt.Println("JWT:\n", r.Token)
}

type cmdMode int

const (
	register cmdMode = iota + 1
	login
)

var (
	loggingFlags string

	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)

	authnCmd = authn.Cmd{
		SubCmd:   "login",
		UserName: "",
		Url:      "http://localhost:8090",
		AAGUID:   "12c85a48-4baf-47bd-b51f-f192871a1511",
		Key:      "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c",
		Counter:  0,
	}
)

func init() {
	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2", "logging startup arguments")
	startServerCmd.StringVar(&authnCmd.Url, "url", authnCmd.Url, "web authn server url")
	startServerCmd.StringVar(&authnCmd.SubCmd, "subcmd", authnCmd.SubCmd, "sub command: login|register")
	startServerCmd.StringVar(&authnCmd.UserName, "name", authnCmd.UserName, "user name")
	startServerCmd.StringVar(&authnCmd.AAGUID, "aaguid", authnCmd.AAGUID, "AAGUID")
	startServerCmd.StringVar(&authnCmd.Key, "key", authnCmd.Key, "authenticator master key")
	startServerCmd.Uint64Var(&authnCmd.Counter, "counter", authnCmd.Counter, "Authenticator's counter, used for cloning detection")
}
