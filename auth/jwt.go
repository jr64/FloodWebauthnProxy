package auth

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/golang-jwt/jwt"
)

type FloodClaims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type JwtOptions struct {
	Secret        string
	TokenValidFor time.Duration
	CookieDomain  string
}

func CheckJwtHandler(proxy *httputil.ReverseProxy, hostname string, jwtSecret string) func(http.ResponseWriter, *http.Request) {

	return func(w http.ResponseWriter, r *http.Request) {

		catchRequest := true

		r.Host = hostname

		if jwtToken, err := r.Cookie("jwt"); err == nil {
			if _, err = verifyJwtToken(jwtToken.Value, jwtSecret); err == nil {
				catchRequest = false
			} else {
				log.Warnf("Error verifying jwt token: %v", err)
			}
		}

		if catchRequest {
			go log.Infof("redirecting %s %s to /webauthn/", r.Method, r.RequestURI)
			http.Redirect(w, r, "/webauthn/", http.StatusFound)
		} else {
			go log.Infof("%s %s", r.Method, r.RequestURI)
			proxy.ServeHTTP(w, r)
		}

	}

}

func verifyJwtToken(token string, secret string) (*FloodClaims, error) {

	//jwt.TimeFunc = func() time.Time { return time.Unix(0, 0) }

	parsedToken, err := jwt.ParseWithClaims(token, &FloodClaims{}, func(token *jwt.Token) (interface{}, error) {

		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(*FloodClaims); ok && parsedToken.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func createJwtToken(claims FloodClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}
