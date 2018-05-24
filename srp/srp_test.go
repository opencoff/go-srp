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

func newAsserter(t *testing.T) func(cond bool, msg string, args ...interface{}) {
	return func(cond bool, msg string, args ...interface{}) {
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
}

type user struct {
	userhash       []byte
	salt, verifier []byte
	p      int
}

type userdb struct {
	p int
	u []*user
}

func newUserDB(uname, pass []byte, p int) (*userdb, error) {

	uh, s, v, err := Verifier(uname, pass, p)
	if err != nil {
		return nil, err
	}

	u := &user{userhash: uh, salt: s, verifier: v, p: p}
	db := &userdb{p: p}

	db.u = append(db.u, u)

	return db, nil
}

// simulated user lookup
func (db *userdb) lookup(uhash []byte) (bool, *user) {
	u := db.u[0]
	return true, u
}

func (db *userdb) verify(t *testing.T, user, pass []byte, goodPw bool) {
	assert := newAsserter(t)

	// setup client session
	c, err := NewClient(user, pass, db.p)
	assert(err == nil, "expected err to be nil; saw %s", err)

	creds := c.Credentials() // this is what we send to server

	ii, aa, err := ServerBegin(creds)
	assert(err == nil, "expected err to be nil; saw %s", err)

	// Begin a new server session by looking up DB using 'ii' as the
	// key; fetch verifier (v), salt from the DB.
	ok, u := db.lookup(ii)
	assert(ok, "can't find user in db")

	s, err := NewServer(ii, u.salt, u.verifier, aa, u.p)
	assert(err == nil, "expected err to be nil; saw %s", err)

	screds := s.Credentials() // send this to client.

	mauth, err := c.Generate(screds) // send the mutual authenticator to server
	assert(err == nil, "expected err to be nil; saw %s", err)

	proof, err := s.ClientOk(mauth) // confirm mutual authenticator and send proof of legit auth
	if goodPw {
		assert(err == nil, "server: bad client auth (%s)", err)
	} else {
		assert(err != nil, "server: expected client to fail")
		return
	}

	// finally, the client should verify the server's proof
	err = c.ServerOk(proof)
	assert(err == nil, "client: bad server (%s)", err)

	// both client and server are authenticated. Now, we generate a
	// mutual secret -- which should be identical

	kc := c.RawKey()
	ks := s.RawKey()

	assert(1 == subtle.ConstantTimeCompare(kc, ks), "key mismatch;\nclient %x, server %x", kc, ks)
}

func TestSRP(t *testing.T) {
	assert := newAsserter(t)
	var user []byte = []byte("user00")
	var goodpass []byte = []byte("secretpassword")
	var badpass []byte = []byte("badpassword")


	bits := []int{1024, 2048, 3072, 4096, 6144, 8192}

	for _, p := range bits {
		t.Logf("Prime bits %d ..\n", p)
		db, err := newUserDB(user, goodpass, p)
		assert(err == nil, "expected err to be nil; saw %s", err)

		db.verify(t, user, goodpass, true)
		db.verify(t, user, badpass, false)
	}
}



func mustDecode(s string) []byte {
	n := len(s)
	b := make([]byte, 0, n)
	var z, x byte
	var shift uint = 4
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case '0' <= c && c <= '9':
			x = c - '0'
		case 'a' <= c && c <= 'f':
			x = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			x = c - 'A' + 10
		case  c == ' ' || c == '\n' || c == '\t':
			continue
		default:
			panic(fmt.Sprintf("invalid hex char %c in %s", c, s))
		}

		if shift == 0 {
			z |= x
			b = append(b, z)
			z = 0
			shift = 4
		} else {
			z |= (x << shift)
			shift -= 4
		}
	}
	if shift != 4 {
		b = append(b, z)
	}
	return b
}
