package main


// Simple test program to test the SRP library
// Author: Sudhi Herle
// April 2014

import (
	"fmt"
	"crypto/subtle"
	"github.com/opencoff/go-srp"
)

func main() {
    bits := 1024
    pass := []byte("password string that's too long")
    i    := []byte("foouser")


    s, err := srp.New(bits)
    if err != nil {
	    panic(err)
    }

    v, err := s.Verifier(i, pass)
    if err != nil {
        panic(err)
    }

    ih, vh := v.Encode()

    // Store ih, vh in durable storage
    fmt.Printf("Verifier Store:\n   %s => %s\n", ih, vh)

    c, err := s.NewClient(i, pass)
    if  err != nil {
        panic(err)
    }

    // client credentials (public key and identity) to send to server
    creds := c.Credentials()

    fmt.Printf("Client Begin; <I, A> --> server:\n   %s\n", creds)

    // Begin the server by parsing the client public key and identity.
    ih, A, err := srp.ServerBegin(creds)
    if err != nil {
        panic(err)
    }

    // Now, pretend to lookup the user db using "I" as the key and
    // fetch salt, verifier etc.
    s, v, err = srp.MakeSRPVerifier(vh)
    if err != nil {
	    panic(err)
    }

    fmt.Printf("Server Begin; <v, A>:\n   %s\n   %x\n", vh, A.Bytes())
    srv, err := s.NewServer(v, A)
    if err != nil {
        panic(err)
    }

    // Generate the credentials to send to client
    creds = srv.Credentials()

    // Send the server public key and salt to server
    fmt.Printf("Server Begin; <s, B> --> client:\n   %s\n", creds)

    // client processes the server creds and generates 
    // a mutual authenticator; the authenticator is sent
    // to the server as proof that the client derived its keys.
    cauth, err := c.Generate(creds)
    if err != nil {
        panic(err)
    }


    fmt.Printf("Client Authenticator: M --> Server\n   %s\n", cauth)

    // Receive the proof of authentication from client
    proof, ok := srv.ClientOk(cauth)
    if !ok {
        panic("client auth failed")
    }

    // Send proof to the client
    fmt.Printf("Server Authenticator: M' --> Server\n   %s\n", proof)


    // Verify the server's proof
    if !c.ServerOk(proof) {
        panic("server auth failed")
    }


    // Now, we have successfully authenticated the client to the
    // server and vice versa.


    kc := c.RawKey()
    ks := srv.RawKey()

    if 1 != subtle.ConstantTimeCompare(kc, ks) {
        panic("Keys are different!")
    }

    fmt.Printf("Client Key: %x\nServer Key: %x\n", kc, ks)
}

// EOF
