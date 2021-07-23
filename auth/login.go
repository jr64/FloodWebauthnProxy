package auth

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"github.com/jr64/FloodWebauthnProxy/session"
	"github.com/jr64/FloodWebauthnProxy/userdb"
	log "github.com/sirupsen/logrus"
)

func BeginLoginHandler(webAuthnCtx *webauthn.WebAuthn, sessionStore *session.Store, userDB *userdb.Userdb) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		username := vars["username"]

		log.Debugf("BeginLogin for user %s", username)

		user, err := userDB.GetUser(username)

		if err != nil {
			log.Errorf("Failed to load user %s from database: %v", username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		options, sessionData, err := webAuthnCtx.BeginLogin(user,
			webauthn.WithUserVerification(
				protocol.VerificationDiscouraged,
			),
		)
		if err != nil {
			log.Warnf("Failed to begin login for user %s: %v", user.Username, err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		err = sessionStore.SaveWebauthnSession("authentication", sessionData, r, w)
		if err != nil {
			log.Errorf("Failed to store session for user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		jsonResponse(w, options, http.StatusOK)
	}

}

func FinishLoginHandler(webAuthnCtx *webauthn.WebAuthn, sessionStore *session.Store, userDB *userdb.Userdb, jwtOptions *JwtOptions) func(w http.ResponseWriter, r *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		vars := mux.Vars(r)
		username := vars["username"]

		log.Debugf("BeginLogin for user %s", username)

		user, err := userDB.GetUser(username)
		if err != nil {
			log.Errorf("Failed to load user %s from database: %v", username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		sessionData, err := sessionStore.GetWebauthnSession("authentication", r)
		if err != nil {
			log.Errorf("Failed to load session data for user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		// in an actual implementation, we should perform additional checks on
		// the returned 'credential', i.e. check 'credential.Authenticator.CloneWarning'
		// and then increment the credentials counter
		credential, err := webAuthnCtx.FinishLogin(user, sessionData, r)
		if err != nil {
			log.Warnf("Failed to finish login for user %s: %v", user.Username, err)
			jsonResponse(w, err.Error(), http.StatusBadRequest)
			return
		}

		if credential.Authenticator.CloneWarning {

			log.Warnf("Authenticator %s of user %s suspected of cloning.", base64.StdEncoding.EncodeToString(credential.PublicKey), user.Username)
			jsonResponse(w, "Authenticator clone detected", http.StatusBadRequest)
			return
		}

		updated := false
		for idx := range user.Credentials {

			curCred := &user.Credentials[idx]

			if bytes.Compare(curCred.PublicKey, credential.PublicKey) == 0 {
				curCred.Authenticator.UpdateCounter(credential.Authenticator.SignCount)
				updated = true
			}
		}

		if !updated {
			log.Errorf("Failed to find Authenticator with Public Key %s to update SignCount data for user %s: %v", base64.StdEncoding.EncodeToString(credential.PublicKey), user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		err = userDB.PutUser(user)
		if err != nil {
			log.Errorf("Failed to update user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		}

		token, err := createJwtToken(FloodClaims{
			Username: user.Username,
			StandardClaims: jwt.StandardClaims{
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(jwtOptions.TokenValidFor).Unix(),
			},
		}, jwtOptions.Secret)

		if err != nil {
			log.Errorf("Error creating jwt token for user %s: %v", user.Username, err)
			jsonResponse(w, nil, http.StatusInternalServerError)
			return
		} else {
			http.SetCookie(w, &http.Cookie{
				Name:     "jwt",
				Value:    token,
				Expires:  time.Now().Add(jwtOptions.TokenValidFor),
				HttpOnly: true,
				Domain:   jwtOptions.CookieDomain,
				Path:     "/",
			})
			//http.Redirect(w, r, "/overview", 302)
			//w.WriteHeader(http.StatusOK)
		}
		// handle successful login
		log.Infof("User %s successfully logged in with authenticator %s (SignCount: %d)", user.Username, base64.StdEncoding.EncodeToString(credential.PublicKey), credential.Authenticator.SignCount)
		jsonResponse(w, "Login Success", http.StatusOK)
	}

}
