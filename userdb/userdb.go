package userdb

import (
	"encoding/json"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"sync"
)

type Userdb struct {
	dirpath string
	mutex   sync.Mutex
}

var db *Userdb

func DB(dir string) (*Userdb, error) {

	if db != nil {
		return db, nil
	}

	dbTmp := &Userdb{
		dirpath: dir,
	}

	err := os.MkdirAll(dir, 644)

	if err == nil {
		db = dbTmp
	}

	return db, err
}

func (db *Userdb) GetUser(name string) (*User, error) {

	db.mutex.Lock()
	defer db.mutex.Unlock()

	data, err := ioutil.ReadFile(path.Join(db.dirpath, url.QueryEscape(name)))

	user := NewUser(name)

	if err == nil {
		err = json.Unmarshal(data, user)
	}

	if _, ok := err.(*os.PathError); ok {
		return user, nil
	} else {
		return user, err
	}
}

func (db *Userdb) PutUser(user *User) error {

	db.mutex.Lock()
	defer db.mutex.Unlock()

	return marshalUserToFile(user)
}

func marshalUserToFile(user *User) error {
	data, err := json.Marshal(user)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(path.Join(db.dirpath, url.QueryEscape(user.Username)), data, 0640)
}
