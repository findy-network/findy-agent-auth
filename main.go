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

	"github.com/duo-labs/webauthn.io/session"
	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/findy-network/findy-agent-auth/enclave"
	"github.com/findy-network/findy-agent-auth/user"
	"github.com/findy-network/findy-common-go/jwt"
	"github.com/findy-network/findy-common-go/utils"
	"github.com/golang/glog"
	"github.com/gorilla/mux"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"

	"github.com/rs/cors"
)

const defaultPort = 8080
const defaultTimeoutSecs = 30

var (
	loggingFlags   string
	port           int = defaultPort
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
	certPath       = "./cert"
	allowCors      = false
	isHTTPS        = false
	testUI         = false
	timeoutSecs    = defaultTimeoutSecs

	startServerCmd = flag.NewFlagSet("server", flag.ExitOnError)

	defaultOrigin = fmt.Sprintf("http://localhost:%d", port)
)

type AccessToken struct {
	Token string `json:"token"`
}

func init() {
	startServerCmd.StringVar(&loggingFlags, "logging", "-logtostderr=true -v=2", "logging startup arguments")
	startServerCmd.IntVar(&port, "port", defaultPort, "server port")
	startServerCmd.StringVar(&agencyAddr, "agency", "guest", "agency gRPC server addr")
	startServerCmd.IntVar(&agencyPort, "gport", 50051, "agency gRPC server port")
	startServerCmd.BoolVar(&agencyInsecure, "agency-insecure", false, "establish insecure connection to agency")
	startServerCmd.StringVar(&rpID, "domain", "localhost", "the site domain name")
	startServerCmd.StringVar(&rpOrigin, "origin", defaultOrigin, "origin URL for Webauthn requests")
	startServerCmd.StringVar(&jwtSecret, "jwt-secret", "", "secure key for JWT token generation")
	startServerCmd.StringVar(&enclaveFile, "sec-file", enclaveFile, "secure enclave DB file name")
	startServerCmd.StringVar(&enclaveBackup, "sec-backup-file", enclaveBackup, "secure enclave DB backup base file name")
	startServerCmd.StringVar(&enclaveKey, "sec-key", enclaveKey, "sec-enc master key, SHA-256, 32-byte hex coded")
	startServerCmd.IntVar(&backupInterval, "sec-backup-interval", backupInterval, "secure enclave backup interval in hours")
	startServerCmd.StringVar(&findyAdmin, "admin", findyAdmin, "admin ID used for this agency ecosystem")
	startServerCmd.StringVar(&certPath, "cert-path", certPath, "cert root path where server and client certificates exist")
	startServerCmd.BoolVar(&allowCors, "cors", allowCors, "allow cross-origin requests")
	startServerCmd.BoolVar(&isHTTPS, "local-tls", isHTTPS, "serve HTTPS")
	startServerCmd.BoolVar(&testUI, "test-ui", testUI, "render test UI")
	startServerCmd.IntVar(&timeoutSecs, "timeout", timeoutSecs, "GRPC call timeout in seconds")
}

func main() {
	defer err2.CatchTrace(func(_ error) {
		glog.Warningln("")
	})
	try.To(startServerCmd.Parse(os.Args[1:]))
	utils.ParseLoggingArgs(loggingFlags)

	u := try.To1(url.Parse(rpOrigin))

	glog.V(3).Infoln(
		"\nlogging:", loggingFlags,
		"\norigin host:", u.Host,
		"\nlisten port:", port,
		"\norigin port:", u.Port(),
		"\nHTTPS ==", isHTTPS,
	)

	try.To(enclave.InitSealedBox(enclaveFile, enclaveBackup, enclaveKey))
	user.Init(certPath, agencyAddr, agencyPort, agencyInsecure)

	if jwtSecret != "" {
		jwt.SetJWTSecret(jwtSecret)
	}

	var err error
	webAuthn = try.To1(webauthn.New(&webauthn.Config{
		RPDisplayName: "Findy Agency", // Display Name for your site
		RPID:          rpID,           // Generally the domain name for your site
		RPOrigin:      rpOrigin,       // The origin URL for WebAuthn requests
	}))
	sessionStore = try.To1(session.NewStore())

	r := mux.NewRouter()

	r.HandleFunc("/register/begin/{username}", BeginRegistration).Methods("GET")
	r.HandleFunc("/register/finish/{username}", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin/{username}", BeginLogin).Methods("GET")
	r.HandleFunc("/login/finish/{username}", FinishLogin).Methods("POST")

	if testUI {
		r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))
	} else {
		r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		})
	}

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
	if isHTTPS {
		certPath = filepath.Join(certPath, "server")
		certFile := filepath.Join(certPath, "server.crt")
		keyFile := filepath.Join(certPath, "server.key")
		glog.V(3).Infoln("starting TLS server with:\n", certFile, "\n", keyFile)
		err = http.ListenAndServeTLS(serverAddress, certFile, keyFile, handler)
	} else {
		err = http.ListenAndServe(serverAddress, handler)
	}
	if err != nil {
		glog.Infoln("listen error:", err)
	}
	backupTickerDone <- struct{}{}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(func(err error) {
		glog.Warningln("begin registration error:", err)
	})

	// get username/friendly name
	vars := mux.Vars(r)
	username, ok := vars["username"]
	glog.V(1).Infoln("begin registration", username)
	if !ok {
		jsonResponse(w, fmt.Errorf("must supply a valid username i.e. foo@bar.com"),
			http.StatusBadRequest)
		return
	}

	var err error

	// get user
	userData, exists := try.To2(enclave.GetUser(username))

	displayName := strings.Split(username, "@")[0]
	if !exists {
		glog.V(2).Infoln("adding new user:", displayName)

		urlParams := r.URL.Query()
		seed := urlParams.Get("seed")
		if seed == "" {
			glog.V(5).Infoln("no seed supplied")
		}

		userData = user.NewUser(username, displayName, seed)
		try.To(enclave.PutUser(userData))
	} else if !jwt.IsValidUser(userData.DID, r.Header["Authorization"]) {
		glog.Warningln("new ator, invalid JWT", userData.DID, displayName)
		jsonResponse(w, fmt.Errorf("invalid token"), http.StatusBadRequest)
		return
	}

	registerOptions := func(credCreationOpts *protocol.PublicKeyCredentialCreationOptions) {
		credCreationOpts.CredentialExcludeList = userData.CredentialExcludeList()
		glog.V(1).Infoln("credexcl:", len(credCreationOpts.CredentialExcludeList))
	}

	defer err2.Handle(&err, func() {
		glog.Errorln("error:", err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
	})

	glog.V(1).Infoln("begin registration to webAuthn")
	options, sessionData := try.To2(webAuthn.BeginRegistration(
		userData,
		registerOptions,
	))
	glog.V(1).Infof("sessionData: %v", sessionData)

	// store session data as marshaled JSON
	glog.V(1).Infoln("store session data")
	try.To(sessionStore.SaveWebauthnSession("registration", sessionData, r, w))

	jsonResponse(w, options, http.StatusOK)
	glog.V(1).Infoln("begin registration end", username)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(func(err error) {
		glog.Warningln("BEGIN finish registration:", err)
	})

	var err error

	// get username
	vars := mux.Vars(r)
	username := vars["username"]
	glog.V(1).Infoln("finish registration", username)

	defer err2.Handle(&err, func() {
		glog.Errorln("error:", err)
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
	})

	glog.V(1).Infoln("getting existing user", username)
	user := try.To1(enclave.GetExistingUser(username))

	glog.V(1).Infoln("get session data for registration")
	sessionData := try.To1(sessionStore.GetWebauthnSession("registration", r))

	glog.V(1).Infoln("call web authn finish registration and getting credential")
	credential := try.To1(webAuthn.FinishRegistration(user, sessionData, r))

	// Add needed data to User
	user.AddCredential(*credential)
	try.To(user.AllocateCloudAgent(findyAdmin, time.Duration(timeoutSecs)*time.Second))
	// Persist that data
	try.To(enclave.PutUser(user))

	jsonResponse(w, "Registration Success", http.StatusOK)
	glog.V(1).Infoln("END finish registration", username)
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(func(err error) {
		glog.Warningln("begin login", err)
	})

	var err error

	// get username
	vars := mux.Vars(r)
	username := vars["username"]
	glog.V(1).Infoln("BEGIN begin login", username)

	defer err2.Handle(&err, func() {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
	})

	// get user
	user := try.To1(enclave.GetExistingUser(username))

	// generate PublicKeyCredentialRequestOptions, session data
	options, sessionData := try.To2(webAuthn.BeginLogin(user))

	// store session data as marshaled JSON
	err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)

	jsonResponse(w, options, http.StatusOK)
	glog.V(1).Infoln("END begin login", username)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	defer err2.Catch(func(err error) {
		glog.Warningln("finish login error:", err)
	})

	var err error

	// get username
	vars := mux.Vars(r)
	username := vars["username"]
	glog.V(1).Infoln("BEGIN finish login:", username)

	defer err2.Handle(&err, func() {
		jsonResponse(w, err.Error(), http.StatusInternalServerError)
	})

	// get user
	user := try.To1(enclave.GetExistingUser(username))

	// load the session data
	sessionData := try.To1(sessionStore.GetWebauthnSession("authentication", r))

	// in an actual implementation, we should perform additional checks on
	// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
	// and then increment the credentials counter
	_ = try.To1(webAuthn.FinishLogin(user, sessionData, r))

	// handle successful login
	jsonResponse(w, &AccessToken{Token: user.JWT()}, http.StatusOK)
	glog.V(1).Infoln("END finish login", username)
}

// from: https://github.com/duo-labs/webauthn.io/blob/3f03b482d21476f6b9fb82b2bf1458ff61a61d41/server/response.go#L15
func jsonResponse(w http.ResponseWriter, d interface{}, c int) {
	defer err2.Catch(func(err error) {
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
	})

	dj := try.To1(json.Marshal(d))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(c)
	glog.V(1).Infof("reply json:\n%s", dj)
	try.To1(fmt.Fprintf(w, "%s", dj))
}
