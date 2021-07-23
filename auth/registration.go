package auth

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/gorilla/mux"
	"github.com/jr64/FloodWebauthnProxy/session"
	"github.com/jr64/FloodWebauthnProxy/userdb"
	log "github.com/sirupsen/logrus"
)

func RegistrationDisabledHandler() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, "Registration is disabled.", http.StatusBadRequest)
	}
}
func BeginRegistrationHandler(webAuthnCtx *webauthn.WebAuthn, sessionStore *session.Store, userDB *userdb.Userdb) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		username, ok := vars["username"]

		log.Debugf("BeginRegistration for user %s", username)

		if !ok {
			jsonResponse(w, fmt.Errorf("Username invalid"), http.StatusBadRequest)
			return
		}

		user, err := userDB.GetUser(username)
		if err != nil {
			log.Errorf("Failed to load user %s from database: %v", username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		residentKey := new(bool)
		*residentKey = false

		// generate PublicKeyCredentialCreationOptions, session data
		options, sessionData, err := webAuthnCtx.BeginRegistration(
			user,
			webauthn.WithExclusions(
				user.CredentialExclusionList(),
			),
			webauthn.WithAuthenticatorSelection(
				protocol.AuthenticatorSelection{
					RequireResidentKey: residentKey,
					UserVerification:   protocol.VerificationPreferred,
				},
			),
		)

		if err != nil {
			log.Warnf("Failed to begin WebAuthn registration for user %s: %v", user.Username, err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = sessionStore.SaveWebauthnSession("registration", sessionData, r, w)
		if err != nil {
			log.Errorf("Failed to store session for user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		err = userDB.PutUser(user)
		if err != nil {
			log.Errorf("Failed to store user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		jsonResponse(w, options, http.StatusOK)
	}
}

func FinishRegistrationHandler(webAuthnCtx *webauthn.WebAuthn, sessionStore *session.Store, userDB *userdb.Userdb) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		username := vars["username"]

		log.Debugf("FinishRegistration for user %s", username)

		user, err := userDB.GetUser(username)
		if err != nil {
			log.Errorf("Failed to load user %s from database: %v", username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		sessionData, err := sessionStore.GetWebauthnSession("registration", r)
		if err != nil {
			log.Errorf("Failed to load session for user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		credential, err := webAuthnCtx.FinishRegistration(user, sessionData, r)
		if err != nil {
			log.Warnf("Failed to finish registration for user %s: %v", user.Username, err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		user.Credentials = append(user.Credentials, *credential)
		err = userDB.PutUser(user)
		if err != nil {
			log.Errorf("Failed to store user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		log.Infof("User %s successfully registered authenticator %s (SignCount: %d)", user.Username, base64.StdEncoding.EncodeToString(credential.PublicKey), credential.Authenticator.SignCount)
		jsonResponse(w, "Registration Success", http.StatusOK)
	}

}
