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
	v *Verifier
}

type userdb struct {
	s *SRP
	u map[string]string
}

func newUserDB(user, pass []byte, p int) (*userdb, error) {

	s, err := New(p)
	if err != nil {
		return nil, err
	}

	v, err := s.Verifier(user, pass)
	if err != nil {
		return nil, err
	}

	ih, vh := v.Encode()

	db := &userdb{
		s: s,
		u: make(map[string]string),
	}

	db.u[ih] = vh

	return db, nil
}

// simulated user lookup
func (db *userdb) lookup(ih string) (bool, string) {
	u, ok := db.u[ih]
	return ok, u
}

func (db *userdb) verify(t *testing.T, user, pass []byte, goodPw bool) {
	assert := newAsserter(t)

	s := db.s // SRP Instance

	// Start an SRP Client instance
	c, err := s.NewClient(user, pass)
	assert(err == nil, "NewClient: %s", err)

	// Credentials to send to server
	creds := c.Credentials() // this is what we send to server

	// client --> sends 'creds' to server

	// In actuality, this is done on the server.
	ih, A, err := ServerBegin(creds)
	assert(err == nil, "ServerBegin: %s", err)

	// Using identity 'ih', lookup the user-db and fetch the encoded verifier.
	ok, vs := db.lookup(ih)
	assert(ok, "can't find user in db")

	// On the server, we create the SRP instance afresh from the verifier.
	s, v, err := MakeSRPVerifier(vs)
	assert(err == nil, "SRPVerifier: %s", err)

	// create a SRP server instance using the verifier and public key
	srv, err := s.NewServer(v, A)
	assert(err == nil, "NewServer: %s", err)

	// Send the salt and Server public Key to client
	sCreds := srv.Credentials()

	// Server  --> sends 'sCreds' to client

	// Client generates a mutual auth and sends to server
	mauth, err := c.Generate(sCreds)
	assert(err == nil, "Client.Generate: %s", err)

	// Client --> sends 'mauth' to server

	// Server validates the mutual authenticator and creates its proof of having derived
	// the same key. This proof is sent to the client.
	proof, ok := srv.ClientOk(mauth)
	if goodPw {
		assert(ok, "server: bad client proof")
	} else {
		assert(!ok, "server: validated bad password")
		return
	}

	// Server  --> sends 'proof' to client

	// finally, the client should verify the server's proof
	ok = c.ServerOk(proof)
	assert(ok, "client: bad client proof")

	// both client and server are authenticated. Now, we generate a
	// mutual secret -- which should be identical

	kc := c.RawKey()
	ks := srv.RawKey()

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
		case c == ' ' || c == '\n' || c == '\t':
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
