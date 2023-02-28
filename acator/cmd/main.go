package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/findy-network/findy-agent-auth/acator/authn"
	"github.com/findy-network/findy-common-go/utils"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

func main() {
	err2.SetPanicTracer(os.Stderr)
	defer err2.Catch(func(err error) {
		glog.Warningln(err)
		os.Exit(1)
	})
	try.To(startServerCmd.Parse(os.Args[1:]))
	utils.ParseLoggingArgs(loggingFlags)

	jsonAPI := false
	if startServerCmd.Arg(0) == "-" {
		authnCmd = authnCmd.TryReadJSON(os.Stdin)
		jsonAPI = true
	}

	if dryRun {
		fmt.Println(string(try.To1(json.MarshalIndent(authnCmd, "", "\t"))))
		return
	}

	r := try.To1(authnCmd.Exec(os.Stdout))

	if jsonAPI {
		fmt.Println(r.String())
	} else {
		fmt.Println(r.Token)
	}
}

var (
	dryRun         bool
	loggingFlags   string
	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)

	authnCmd = authn.Cmd{
		SubCmd:         "login",
		UserName:       "",
		Url:            "http://localhost:8090",
		RegisterBegin:  "%s/register/begin/%s?seed=%s",
		RegisterFinish: "%s/register/finish/%s",
		LoginBegin:     "%s/login/begin/%s",
		LoginFinish:    "%s/login/finish/%s",
		AAGUID:         "12c85a48-4baf-47bd-b51f-f192871a1511",
		Key:            "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c",
		Counter:        0,
	}
)

func init() {
	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2", "logging startup arguments")
	startServerCmd.StringVar(&authnCmd.Url, "url", authnCmd.Url, "web authn server url")
	startServerCmd.StringVar(&authnCmd.RegisterBegin, "reg-begin", authnCmd.RegisterBegin, "format string to build endpoint")
	startServerCmd.StringVar(&authnCmd.RegisterFinish, "reg-finish", authnCmd.RegisterFinish, "format string to build endpoint")
	startServerCmd.StringVar(&authnCmd.LoginBegin, "log-begin", authnCmd.LoginBegin, "format string to build endpoint")
	startServerCmd.StringVar(&authnCmd.LoginFinish, "log-finish", authnCmd.LoginFinish, "format string to build endpoint")
	startServerCmd.StringVar(&authnCmd.SubCmd, "subcmd", authnCmd.SubCmd, "sub command: login|register")
	startServerCmd.StringVar(&authnCmd.UserName, "name", authnCmd.UserName, "user name")
	startServerCmd.StringVar(&authnCmd.AAGUID, "aaguid", authnCmd.AAGUID, "AAGUID")
	startServerCmd.StringVar(&authnCmd.Key, "key", authnCmd.Key, "authenticator master key")
	startServerCmd.StringVar(&authnCmd.Origin, "origin", authnCmd.Origin, "use if origin needs to be different than from -url")
	startServerCmd.Uint64Var(&authnCmd.Counter, "counter", authnCmd.Counter, "Authenticator's counter, used for cloning detection")

	startServerCmd.BoolVar(&dryRun, "dry-run", dryRun, "dry run, e.g. output current cmd as JSON")
}
