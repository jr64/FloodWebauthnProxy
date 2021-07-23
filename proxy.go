package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jr64/FloodWebauthnProxy/auth"
	"github.com/jr64/FloodWebauthnProxy/session"
	"github.com/jr64/FloodWebauthnProxy/userdb"
)

func main() {

	log.SetFormatter(&log.TextFormatter{TimestampFormat: "2006-01-02 15:04:05", FullTimestamp: true})
	log.SetFormatter(&log.TextFormatter{ForceColors: true})

	viper.SetEnvPrefix("FLOODPROXY")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	flag.StringP("upstream", "u", "", "upstream Flood server")
	flag.StringP("server-address", "s", ":8080", "ip address to listen on")
	flag.BoolP("enable-registration", "r", false, "allow anyone to register new authenticators (disable this after initial setup)")

	flag.String("rp-display-name", "Flood", "WebAuthn relying party display name")
	flag.String("rp-id", "", "WebAuthn relying party ID")
	flag.String("rp-origin", "", "WebAuthn relying party origin")

	flag.StringP("userdb-directory", "d", "users", "directory where user data will be stored")
	flag.StringP("jwt-secret", "j", "", "secret used to sign JWT tokens")
	flag.IntP("jwt-duration", "t", 24*7, "time in hours that created JWT tokens will be valid")

	flag.BoolP("insecure-skip-verify-tls", "k", false, "skip verifying TLS certificate of upstream")

	flag.BoolP("verbose", "v", false, "print debug messages")

	flag.CommandLine.SortFlags = false
	flag.Parse()

	// replace - with _ in flags so we can use the snake_case version when accessing through viper
	normalizeFunc := flag.CommandLine.GetNormalizeFunc()
	flag.CommandLine.SetNormalizeFunc(func(fs *pflag.FlagSet, name string) pflag.NormalizedName {
		result := normalizeFunc(fs, name)
		name = strings.ReplaceAll(string(result), "-", "_")
		return pflag.NormalizedName(name)
	})

	viper.BindPFlags(flag.CommandLine)

	if viper.GetBool("verbose") {
		log.SetLevel(log.DebugLevel)
	}

	webAuthnCtx, err := webauthn.New(&webauthn.Config{
		RPDisplayName: viper.GetString("rp_display_name"), // Display Name for your site
		RPID:          viper.GetString("rp_id"),           // Generally the domain name for your site
		RPOrigin:      viper.GetString("rp_origin"),       // The origin URL for WebAuthn requests
		// RPIcon:        "http://localhost:8080/webauthn/icon.jpg", // Optional icon URL for your site
	})

	if err != nil {
		log.Fatal("Failed to create WebAuthn from config:", err)
	}

	sessionStore, err := session.NewStore()

	if err != nil {
		log.Fatal("Failed to create session store:", err)
	}

	db, err := userdb.DB(viper.GetString("userdb_directory"))
	if err != nil {
		log.Fatal("Failed to create user database directory:", err)
	}

	upstream := viper.GetString("upstream")

	remote, err := url.Parse(upstream)
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(webAuthnCtx.Config.RPOrigin)
	if err != nil {
		log.Fatalf("Failed to parse RP Origin %s: %v", webAuthnCtx.Config.RPOrigin, err)
	}
	jwtOpts := &auth.JwtOptions{
		Secret:        viper.GetString("jwt_secret"),
		TokenValidFor: time.Hour * time.Duration(viper.GetInt("jwt_duration")),
		CookieDomain:  u.Host,
	}

	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.FlushInterval = -1

	if viper.GetBool("insecure_skip_verify_tls") {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	r := mux.NewRouter()

	if viper.GetBool("enable_registration") {
		r.HandleFunc("/webauthn/register/begin/{username}", auth.BeginRegistrationHandler(webAuthnCtx, sessionStore, db)).Methods("POST")
		r.HandleFunc("/webauthn/register/finish/{username}", auth.FinishRegistrationHandler(webAuthnCtx, sessionStore, db)).Methods("POST")
	} else {
		r.HandleFunc("/webauthn/register/begin/{username}", auth.RegistrationDisabledHandler()).Methods("POST")
		r.HandleFunc("/webauthn/register/finish/{username}", auth.RegistrationDisabledHandler()).Methods("POST")
	}

	r.HandleFunc("/webauthn/login/begin/{username}", auth.BeginLoginHandler(webAuthnCtx, sessionStore, db)).Methods("POST")
	r.HandleFunc("/webauthn/login/finish/{username}", auth.FinishLoginHandler(webAuthnCtx, sessionStore, db, jwtOpts)).Methods("POST")
	staticDir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	staticDir = path.Join(staticDir, "./static")
	r.PathPrefix("/webauthn/").Handler(http.StripPrefix("/webauthn/", http.FileServer(http.Dir(staticDir))))
	r.PathPrefix("/").HandlerFunc(auth.CheckJwtHandler(proxy, remote.Host, jwtOpts.Secret))

	serverAddress := viper.GetString("server_address")
	log.Info("starting server at", serverAddress)
	log.Fatal(http.ListenAndServe(serverAddress, r))

}
