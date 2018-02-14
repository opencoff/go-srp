// self test for srp
//
// Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
// License: MIT
//

package srp

import (
	"fmt"

	"runtime"
	"testing"

	"crypto/subtle"
)

func assert(t *testing.T, cond bool, msg string, args ...interface{}) {

	if cond {
		return
	}

	_, file, line, ok := runtime.Caller(1)
	if !ok {
		file = "???"
		line = 0
	}

	s := fmt.Sprintf(msg, args...)
	t.Fatalf("%s: %d: Assertion failed: %s\n", file, line, s)
}

const primeBits = 2048

type user struct {
	userhash       []byte
	salt, verifier []byte
	primeBits      int
}

type userdb struct {
	u []*user
}

func newUserDB(uname, pass []byte) (*userdb, error) {

	uh, s, v, err := Verifier(uname, pass, primeBits)
	if err != nil {
		return nil, err
	}

	u := &user{userhash: uh, salt: s, verifier: v, primeBits: primeBits}
	db := &userdb{}

	db.u = append(db.u, u)

	return db, nil
}

// simulated user lookup
func (db *userdb) lookup(uhash []byte) (bool, *user) {
	u := db.u[0]
	return true, u
}

func (db *userdb) verify(t *testing.T, user, pass []byte, goodPw bool) {

	// setup client session
	c, err := NewClient(user, pass, primeBits)
	assert(t, err == nil, "expected err to be nil; saw %s", err)

	creds := c.Credentials() // this is what we send to server

	ii, aa, err := ServerBegin(creds)
	assert(t, err == nil, "expected err to be nil; saw %s", err)

	// Begin a new server session by looking up DB using 'ii' as the
	// key; fetch verifier (v), salt from the DB.
	ok, u := db.lookup(ii)
	assert(t, ok, "can't find user in db")

	s, err := NewServer(ii, u.salt, u.verifier, aa, primeBits)
	assert(t, err == nil, "expected err to be nil; saw %s", err)

	screds := s.Credentials() // send this to client.

	mauth, err := c.Generate(screds) // send the mutual authenticator to server
	assert(t, err == nil, "expected err to be nil; saw %s", err)

	proof, err := s.ClientOk(mauth) // confirm mutual authenticator and send proof of legit auth
	if goodPw {
		assert(t, err == nil, "server: bad client auth (%s)", err)
	} else {
		assert(t, err != nil, "server: expected client to fail")
		return
	}

	// finally, the client should verify the server's proof
	err = c.ServerOk(proof)
	assert(t, err == nil, "client: bad server (%s)", err)

	// both client and server are authenticated. Now, we generate a
	// mutual secret -- which should be identical

	kc := c.RawKey()
	ks := s.RawKey()

	assert(t, 1 == subtle.ConstantTimeCompare(kc, ks), "key mismatch;\nclient %x, server %x", kc, ks)
}

func TestGood(t *testing.T) {
	var user []byte = []byte("user00")
	var goodpass []byte = []byte("secretpassword")
	var badpass []byte = []byte("badpassword")

	db, err := newUserDB(user, goodpass)
	assert(t, err == nil, "expected err to be nil; saw %s", err)

	db.verify(t, user, goodpass, true)
	db.verify(t, user, badpass, false)
}
