package userdb

import (
	"crypto/rand"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

type User struct {
	Id          []byte
	Username    string
	Credentials []webauthn.Credential
}

func NewUser(Username string) *User {

	user := &User{}
	user.Id = make([]byte, 8)
	rand.Read(user.Id)

	user.Username = Username

	return user
}

// User ID according to the Relying Party
func (u User) WebAuthnID() []byte {
	return u.Id
}

// User Name according to the Relying Party
func (u User) WebAuthnName() string {
	return u.Username
}

// Display Name of the user
func (u User) WebAuthnDisplayName() string {
	return u.Username
}

// User's icon url
func (u User) WebAuthnIcon() string {
	return ""
}

// Credentials owned by the user
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func (u User) CredentialExclusionList() []protocol.CredentialDescriptor {

	credentialExclusionList := make([]protocol.CredentialDescriptor, len(u.Credentials))

	for idx, cred := range u.Credentials {
		credentialExclusionList[idx] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
	}

	return credentialExclusionList
}
