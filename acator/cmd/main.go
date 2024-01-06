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
	// we use err2's std log and route it to our glog outputs.
	glog.CopyStandardLogTo("ERROR")

	defer err2.Catch() // this'll write errors to our glog automatically.

	try.To(startServerCmd.Parse(os.Args[1:]))
	utils.ParseLoggingArgs(loggingFlags)
	if panicTrace {
		err2.SetPanicTracer(os.Stderr)
	}
	if errTrace {
		err2.SetErrorTracer(os.Stderr)
	}

	jsonAPI := false
	if startServerCmd.Arg(0) == "-" {
		authnCmd = authnCmd.TryReadJSON(os.Stdin)
		jsonAPI = true
	} else if fname := startServerCmd.Arg(0); fname != "" {
		glog.V(2).Infoln("fname:", fname)
		f := try.To1(os.Open(fname))
		defer f.Close()
		authnCmd = authnCmd.TryReadJSON(f)
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
	errTrace, panicTrace bool

	dryRun         bool
	loggingFlags   string
	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)

	authnCmd = authn.Cmd{
		SubCmd:     "login",
		UserName:   "",
		CookiePath: "",
		URL:        "http://localhost:8090",

		RegisterBegin: authn.Endpoint{
			Method:  "GET",
			Path:    "%s/register/begin/%s?seed=%s",
			Payload: "",
		},

		RegisterFinish: authn.Endpoint{
			Method:  "POST",
			Path:    "%s/register/finish/%s",
			Payload: "",
		},

		LoginBegin: authn.Endpoint{
			Method:  "GET",
			Path:    "%s/login/begin/%s",
			Payload: "",
		},

		LoginFinish: authn.Endpoint{
			Method:  "POST",
			Path:    "%s/login/finish/%s",
			Payload: "",
		},

		AAGUID:  "12c85a48-4baf-47bd-b51f-f192871a1511",
		Key:     "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c",
		Counter: 0,
	}
)

func init() {
	startServerCmd.BoolVar(&errTrace, "et", false, "enables error stack tracing")
	startServerCmd.BoolVar(&panicTrace, "pt", false, "enables panic stack tracing")

	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2",
		"logging startup arguments")
	startServerCmd.StringVar(&authnCmd.URL, "url", authnCmd.URL, "web authn server url")
	startServerCmd.StringVar(&authnCmd.CookieFile, "cookies", authnCmd.CookieFile,
		"cookies to store between calls")
	startServerCmd.StringVar(&authnCmd.CookiePath, "cookie-path", authnCmd.CookiePath,
		"path to page which loads needed cookies")

	startServerCmd.StringVar(&authnCmd.RegisterBegin.Path, "reg-begin",
		authnCmd.RegisterBegin.Path, "format string to build endpoint path")
	startServerCmd.StringVar(&authnCmd.RegisterFinish.Path, "reg-finish",
		authnCmd.RegisterFinish.Path, "format string to build endpoint path")
	startServerCmd.StringVar(&authnCmd.LoginBegin.Path, "log-begin",
		authnCmd.LoginBegin.Path, "format string to build endpoint path")
	startServerCmd.StringVar(&authnCmd.LoginFinish.Path, "log-finish",
		authnCmd.LoginFinish.Path, "format string to build endpoint path")

	startServerCmd.StringVar(&authnCmd.RegisterBegin.Method, "reg-begin-met",
		authnCmd.RegisterBegin.Method, "format string to build endpoint method")
	startServerCmd.StringVar(&authnCmd.RegisterFinish.Method, "reg-finish-met",
		authnCmd.RegisterFinish.Method, "format string to build endpoint method")
	startServerCmd.StringVar(&authnCmd.LoginBegin.Method, "log-begin-met",
		authnCmd.LoginBegin.Method, "format string to build endpoint method")
	startServerCmd.StringVar(&authnCmd.LoginFinish.Method, "log-finish-met",
		authnCmd.LoginFinish.Method, "format string to build endpoint method")

	startServerCmd.StringVar(&authnCmd.RegisterBegin.Payload, "reg-begin-pl",
		authnCmd.RegisterBegin.Payload, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.RegisterFinish.Payload, "reg-finish-pl",
		authnCmd.RegisterFinish.Payload, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.LoginBegin.Payload, "log-begin-pl",
		authnCmd.LoginBegin.Payload, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.RegisterBegin.InPL, "reg-begin-pl-in",
		authnCmd.RegisterBegin.InPL, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.LoginBegin.InPL, "log-begin-pl-in",
		authnCmd.LoginBegin.InPL, "format string to build endpoint payload JSON template")
	startServerCmd.StringVar(&authnCmd.LoginBegin.MiddlePL, "log-begin-pl-middle",
		authnCmd.LoginBegin.MiddlePL, "format string to build endpoint payload JSON template to SEND")
	startServerCmd.StringVar(&authnCmd.RegisterBegin.MiddlePL, "reg-begin-pl-middle",
		authnCmd.RegisterBegin.MiddlePL, "format string to build endpoint payload JSON template to SEND")
	startServerCmd.StringVar(&authnCmd.LoginFinish.Payload, "log-finish-pl",
		authnCmd.LoginFinish.Payload, "format string to build endpoint payload JSON template")

	startServerCmd.StringVar(&authnCmd.SubCmd, "subcmd", authnCmd.SubCmd, "sub command: login|register")
	startServerCmd.StringVar(&authnCmd.UserName, "name", authnCmd.UserName, "user name")
	startServerCmd.StringVar(&authnCmd.AAGUID, "aaguid", authnCmd.AAGUID, "AAGUID")
	startServerCmd.StringVar(&authnCmd.Key, "key", authnCmd.Key, "authenticator master key")
	startServerCmd.StringVar(&authnCmd.Origin, "origin", authnCmd.Origin, "use if origin needs to be different than from -url")
	startServerCmd.Uint64Var(&authnCmd.Counter, "counter", authnCmd.Counter, "Authenticator's counter, used for cloning detection")

	startServerCmd.BoolVar(&dryRun, "dry-run", dryRun, "dry run, e.g. output current cmd as JSON")
}
