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
	// Marshal the server for use later as-if the client can't remain connected
	srv_m := srv.Marshal()

	// Client generates a mutual auth and sends to server
	mauth, err := c.Generate(sCreds)
	assert(err == nil, "Client.Generate: %s", err)

	// Client --> sends 'mauth' to server
	// Unmarshal the previously marshaled server for use after the client reconnects
	srv_um, err := UnmarshalServer(srv_m)
	assert(err == nil, "UnmarshalServer: %s", err)

	// Server validates the mutual authenticator and creates its proof of having derived
	// the same key. This proof is sent to the client.
	proof, ok := srv_um.ClientOk(mauth)
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
	ks := srv_um.RawKey()

	assert(subtle.ConstantTimeCompare(kc, ks) == 1, "key mismatch;\nclient %x, server %x", kc, ks)
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

