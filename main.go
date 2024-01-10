package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/findy-network/findy-agent-auth/enclave"
	"github.com/findy-network/findy-agent-auth/session"
	"github.com/findy-network/findy-agent-auth/user"
	myhttp "github.com/findy-network/findy-common-go/http"
	"github.com/findy-network/findy-common-go/jwt"
	"github.com/findy-network/findy-common-go/utils"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"

	"github.com/rs/cors"
)

const defaultPort = 8080
const defaultTimeoutSecs = 30

var (
	loggingFlags   string
	port           = defaultPort
	agencyAddr     string
	agencyPort     int
	agencyInsecure bool
	rpID           string
	rpOrigin       string
	jwtSecret      string
	webAuthn       *webauthn.WebAuthn
	sessionStore   *session.Store
	enclaveFile    = "fido-enclave.bolt"
	enclaveBackup  = ""
	enclaveKey     = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	backupInterval = 24 // hours
	findyAdmin     = "findy-root"
	certPath       = ""
	allowCors      = false
	isHTTPS        = false
	testUI         = false
	timeoutSecs    = defaultTimeoutSecs

	// startServereCmd = flag.NewFlagSet("server", flag.ExitOnError)

	defaultOrigin = fmt.Sprintf("http://localhost:%d", port)
)

type AccessToken struct {
	Token string `json:"token"`
}

func init() {
	flag.StringVar(&loggingFlags, "logging", "", "logging startup arguments")
	flag.IntVar(&port, "port", defaultPort, "server port")
	flag.StringVar(&agencyAddr, "agency", "guest", "agency gRPC server addr")
	flag.IntVar(&agencyPort, "gport", 50051, "agency gRPC server port")
	flag.BoolVar(&agencyInsecure, "agency-insecure", false, "establish insecure connection to agency")
	flag.StringVar(&rpID, "domain", "localhost", "RPID, usually domain without a scheme and port (deprecated)")
	flag.StringVar(&rpID, "rpid", "http://localhost", "usually domain without a scheme and port")
	flag.StringVar(&rpOrigin, "origin", defaultOrigin, "origin URL for Webauthn requests")
	flag.StringVar(&jwtSecret, "jwt-secret", "", "secure key for JWT token generation")
	flag.StringVar(&enclaveFile, "sec-file", enclaveFile, "secure enclave DB file name")
	flag.StringVar(&enclaveBackup, "sec-backup-file", enclaveBackup, "secure enclave DB backup base file name")
	flag.StringVar(&enclaveKey, "sec-key", enclaveKey, "sec-enc master key, SHA-256, 32-byte hex coded")
	flag.IntVar(&backupInterval, "sec-backup-interval", backupInterval, "secure enclave backup interval in hours")
	flag.StringVar(&findyAdmin, "admin", findyAdmin, "admin ID used for this agency ecosystem")
	flag.StringVar(&certPath, "cert-path", certPath, "cert root path where server and client certificates exist")
	flag.BoolVar(&allowCors, "cors", allowCors, "allow cross-origin requests")
	flag.BoolVar(&isHTTPS, "local-tls", isHTTPS, "serve HTTPS")
	flag.BoolVar(&testUI, "test-ui", testUI, "render test UI home page")
	flag.IntVar(&timeoutSecs, "timeout", timeoutSecs, "GRPC call timeout in seconds")
}

// define dev/null for all operation systems, until it's in err2 // TODO:
type nulWriter struct{}

func (nulWriter) Write([]byte) (int, error) { return 0, nil }

func main() {
	defer err2.Catch()

	flagParse()
	setupEnv()
	r := newMuxWithRoutes()

	var handler http.Handler = r
	if allowCors {
		hCors := cors.New(cors.Options{
			AllowedOrigins:   []string{rpOrigin},
			AllowCredentials: true,
			Debug:            true,
		})
		handler = hCors.Handler(r)
	}

	backupTickerDone := enclave.BackupTicker(time.Duration(backupInterval) * time.Hour)

	serverAddress := fmt.Sprintf(":%d", port)
	if glog.V(1) {
		glog.Infoln("starting server at", serverAddress)
	}
	var shutdownCh <-chan os.Signal
	if isHTTPS {
		certPath = filepath.Join(certPath, "server")
		certFile := filepath.Join(certPath, "server.crt")
		keyFile := filepath.Join(certPath, "server.key")
		glog.V(3).Infoln("starting TLS server with:\n", certFile, "\n", keyFile)
		server := &http.Server{Addr: serverAddress, Handler: handler}
		shutdownCh = myhttp.Run(server, certFile, keyFile)
	} else {
		server := &http.Server{Addr: serverAddress, Handler: handler}
		shutdownCh = myhttp.Run(server)
	}
	glog.V(3).Infoln("serving...")
	<-shutdownCh
	glog.V(1).Infoln("shutdown triggered successfully")
	myhttp.GracefulStop()

	// memory db dosen't implement backups and this is more sanitity issue than a
	// real thing
	if backupTickerDone != nil {
		backupTickerDone <- struct{}{}
	}
}

func newMuxWithRoutes() *mux.Router {
	r := mux.NewRouter()

	// Our legacy endpoints
	r.HandleFunc("/register/begin/{username}", oldBeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", oldFinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", oldBeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", oldFinishLogin).Methods("POST")

	// New Fido reference standard endpoints
	r.HandleFunc("/assertion/options", BeginLogin).Methods("POST")
	r.HandleFunc("/assertion/result", FinishLogin).Methods("POST")
	r.HandleFunc("/attestation/options", BeginRegistration).Methods("POST")
	r.HandleFunc("/attestation/result", FinishRegistration).Methods("POST")

	if testUI {
		glog.V(2).Info("testUI call")
		r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))
	} else {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			try.To1(fmt.Fprintln(w,
				"NO UI in current running mode, restart w/ -testui"))
		})
	}
	return r
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("begin registration error:", err)
	}))

	var (
		err         error
		userCreated bool
	)
	// get username/friendly name

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return err
	})

	// get username
	var uInfo userInfo
	try.To(json.NewDecoder(r.Body).Decode(&uInfo))
	username := uInfo.Username

	// get user
	userData, exists := try.To2(enclave.GetUser(username))

	displayName := strings.Split(username, "@")[0]
	if !exists {
		glog.V(2).Infoln("adding new user:", displayName)
		if uInfo.Seed == "" {
			glog.V(5).Infoln("no seed supplied")
		}
		userData = user.New(username, displayName, uInfo.Seed)
		try.To(enclave.PutUser(userData))
		userCreated = true
	} else if !jwt.IsValidUser(userData.DID, r.Header["Authorization"]) {
		glog.Warningln("new ator, invalid JWT", userData.DID, displayName)
		jsonResponse(w, fmt.Errorf("invalid token"), http.StatusBadRequest)
		return
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = userData.CredentialExcludeList()
		glog.V(1).Infoln("credexcl:", len(credCreationOpts.CredentialExcludeList))
	}

	defer err2.Handle(&err, func(err error) error {
		glog.Errorln("error:", err)
		if userCreated {
			try.Out(enclave.RemoveUser(username)).
				Logf("cannot cleanup (%s)", username)
		}
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return err
	})

	glog.V(1).Infoln("BEGIN (new) registration to webAuthn")
	options, sessionData := try.To2(webAuthn.BeginRegistration(
		userData,
		registerOptions,
	))
	glog.V(1).Infof("sessionData: %v", sessionData)

	assert.INotNil(sessionStore)
	// store session data as marshaled JSON
	glog.V(1).Infoln("store session data")
	try.To(sessionStore.SaveWebauthnSession("registration", sessionData, r, w))
	try.To(enclave.PutSessionUser(sessionData.UserID, userData))

	jsonResponse(w, options.Response, http.StatusOK)
	glog.V(1).Infoln("BEGIN (new) registration end", username)
}

type userInfo struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName,omitempty"`

	UserVerification string `json:"userVerification,omitempty"`

	Seed string `json:"seed,omitempty"`
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("BEGIN finish registration:", err)
	}))

	var err error

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return err
	})

	assert.INotNil(sessionStore)
	glog.V(1).Infoln("get session data for registration")
	sessionData := try.To1(sessionStore.GetWebauthnSession("registration", r))

	user := try.To1(enclave.GetExistingSessionUser(sessionData.UserID))
	glog.V(1).Infoln("FINISH (new) registration", user.Name)

	defer err2.Handle(&err, func(err error) error {
		glog.Errorln("error:", err)

		// try to remove added user as registration failed
		errRm := enclave.RemoveUser(user.Name)
		if errRm != nil {
			err = fmt.Errorf("finsish reg: %w: %w", err, errRm)
		}
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return nil
	})

	glog.V(1).Infoln("call web authn finish registration and getting credential")
	credential := try.To1(webAuthn.FinishRegistration(user, sessionData, r))

	// Add needed data to User
	user.AddCredential(*credential)
	try.To(user.AllocateCloudAgent(findyAdmin, time.Duration(timeoutSecs)*time.Second)) //nolint: contextcheck
	// Persist that data
	try.To(enclave.PutUser(user))

	jsonResponse(w, "Registration Success", http.StatusOK)
	glog.V(1).Infoln("END (new) finish registration", user.Name)

	_ = enclave.RemoveSessionUser(sessionData.UserID)
}

type loginUserInfo struct {
	Username string `json:"username"`
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("begin login", err)
	}))

	glog.V(1).Infoln("END (new) begin login")
	var err error

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return err
	})

	var uInfo loginUserInfo
	try.To(json.NewDecoder(r.Body).Decode(&uInfo))
	username := uInfo.Username

	user := try.To1(enclave.GetExistingUser(username))

	options, sessionData := try.To2(webAuthn.BeginLogin(user))

	try.To(sessionStore.SaveWebauthnSession("authentication", sessionData, r, w))
	try.To(enclave.PutSessionUser(sessionData.UserID, user))

	jsonResponse(w, options.Response, http.StatusOK)
	glog.V(1).Infoln("END (new) egin login", username)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("finish login error:", err)
	}))

	var err error

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusBadRequest)
		return err
	})

	glog.V(1).Infoln("get session data for finshing login")
	sessionData := try.To1(sessionStore.GetWebauthnSession("authentication", r))

	user := try.To1(enclave.GetExistingSessionUser(sessionData.UserID))

	username := user.Name
	glog.V(1).Infoln("BEGIN (new) finish login:", username)

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return err
	})

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	try.To1(webAuthn.FinishLogin(user, sessionData, r))

	jsonResponse(w, &AccessToken{Token: user.JWT()}, http.StatusOK)
	glog.V(1).Infoln("END (new) finish login", username)
}

// from: https://github.com/go-webauthn/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Errorf("json response error: %s", err)
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	}))

	dj := try.To1(json.Marshal(d))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	glog.V(1).Infof("reply json:\n%s", dj)
	try.To1(fmt.Fprintf(w, "%s", dj))
}

func oldBeginRegistration(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("begin registration error:", err)
	}))

	vars := mux.Vars(r)
	username, ok := vars["username"]
	glog.V(1).Infoln("begin registration", username)
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"),
			http.StatusBadRequest)
		return
	}

	var (
		err         error
		userCreated bool
	)

	userData, exists := try.To2(enclave.GetUser(username))

	displayName := strings.Split(username, "@")[0]
	if !exists {
		glog.V(2).Infoln("adding new user:", displayName)

		urlParams := r.URL.Query()
		seed := urlParams.Get("seed")
		if seed == "" {
			glog.V(5).Infoln("no seed supplied")
		}

		userData = user.New(username, displayName, seed)
		try.To(enclave.PutUser(userData))
		userCreated = true
	} else if !jwt.IsValidUser(userData.DID, r.Header["Authorization"]) {
		glog.Warningln("new ator, invalid JWT", userData.DID, displayName)
		jsonResponse(w, fmt.Errorf("invalid token"), http.StatusBadRequest)
		return
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = userData.CredentialExcludeList()
		glog.V(1).Infoln("credexcl:", len(credCreationOpts.CredentialExcludeList))
	}

	defer err2.Handle(&err, func(err error) error {
		glog.Errorln("error:", err)
		if userCreated {
			try.Out(enclave.RemoveUser(username)).
				Logf("cannot cleanup (%s)", username)
		}
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return err
	})

	glog.V(1).Infoln("begin registration to webAuthn")
	options, sessionData := try.To2(webAuthn.BeginRegistration(
		userData,
		registerOptions,
	))
	glog.V(1).Infof("sessionData: %v", sessionData)

	glog.V(1).Infoln("store session data")
	try.To(sessionStore.SaveWebauthnSession("registration", sessionData, r, w))

	jsonResponse(w, options, http.StatusOK)
	glog.V(1).Infoln("begin registration end", username)
}

func oldFinishRegistration(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("BEGIN finish registration:", err)
	}))

	var err error

	vars := mux.Vars(r)
	username := vars["username"]
	glog.V(1).Infoln("finish registration", username)

	defer err2.Handle(&err, func(err error) error {
		glog.Errorln("error:", err)

		try.Out(enclave.RemoveUser(username)).
			Logf("cannot cleanup (%s)", username)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return err
	})

	glog.V(1).Infoln("getting existing user", username)
	user := try.To1(enclave.GetExistingUser(username))

	glog.V(1).Infoln("get session data for registration")
	sessionData := try.To1(sessionStore.GetWebauthnSession("registration", r))

	glog.V(1).Infoln("call web authn finish registration and getting credential")
	credential := try.To1(webAuthn.FinishRegistration(user, sessionData, r))

	user.AddCredential(*credential)
	try.To(user.AllocateCloudAgent(findyAdmin, time.Duration(timeoutSecs)*time.Second)) //nolint: contextcheck
	try.To(enclave.PutUser(user))

	jsonResponse(w, "Registration Success", http.StatusOK)
	glog.V(1).Infoln("END finish registration", username)
}

func oldBeginLogin(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("begin login", err)
	}))

	var err error

	vars := mux.Vars(r)
	username := vars["username"]
	glog.V(1).Infoln("BEGIN begin login", username)

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return err
	})

	user := try.To1(enclave.GetExistingUser(username))
	options, sessionData := try.To2(webAuthn.BeginLogin(user))
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)

	jsonResponse(w, options, http.StatusOK)
	glog.V(1).Infoln("END begin login", username)
}

func oldFinishLogin(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(err2.Err(func(err error) {
		glog.Warningln("finish login error:", err)
	}))

	var err error

	vars := mux.Vars(r)
	username := vars["username"]
	glog.V(1).Infoln("BEGIN finish login:", username)

	defer err2.Handle(&err, func(err error) error {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
		return err
	})

	user := try.To1(enclave.GetExistingUser(username))

	sessionData := try.To1(sessionStore.GetWebauthnSession("authentication", r))

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	try.To1(webAuthn.FinishLogin(user, sessionData, r))

	jsonResponse(w, &AccessToken{Token: user.JWT()}, http.StatusOK)
	glog.V(1).Infoln("END finish login", username)
}

func flagParse() {
	// our default is to ...
	err2.SetLogTracer(&nulWriter{}) // .. suppress logging from err2
	//err2.SetLogTracer(err2.Stdnull) // TODO: until

	os.Args = append(os.Args,
		"-logtostderr", // todo: should be the first if we want to change this
	)
	//try.To(startServereCmd.Parse(os.Args[1:]))
	flag.Parse()
	if loggingFlags != "" {
		// let loggingFlags overwrite logging flags
		utils.ParseLoggingArgs(loggingFlags)
	}

	if glog.V(1) { // means == V >= 1
		glog.CopyStandardLogTo("ERROR") // for err2
	}
}

func setupEnv() {
	u := try.To1(url.Parse(rpOrigin))

	glog.V(2).Infoln(
		"\nlogging:", loggingFlags,
		"\norigin host:", u.Host,
		"\nlisten port:", port,
		"\norigin port:", u.Port(),
		"\nHTTPS ==", isHTTPS,
		"\nRPID ==", rpID,
	)

	try.To(enclave.InitSealedBox(enclaveFile, enclaveBackup, enclaveKey))
	user.Init(certPath, agencyAddr, agencyPort, agencyInsecure)

	if jwtSecret != "" {
		jwt.SetJWTSecret(jwtSecret)
	}

	webAuthn = try.To1(webauthn.New(&webauthn.Config{
		RPDisplayName: "Findy Agency",     // Display Name for your site
		RPID:          rpID,               // Generally the domain name for your site
		RPOrigins:     []string{rpOrigin}, // The origin URL for WebAuthn requests
		// old deprecated version:
		//RPOrigin:      rpOrigin,       // The origin URL for WebAuthn requests
	}))
	sessionStore = try.To1(session.NewStore())
}

const (
	urlBeginLogin     = "/assertion/options"
	urlFinishLogin    = "/assertion/result"
	urlBeginRegister  = "/attestation/options"
	urlFinishRegister = "/attestation/result"
)
