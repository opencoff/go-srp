package main


// Simple test program to test the SRP library
// Author: Sudhi Herle
// April 2014

import "fmt"
import "crypto/subtle"

import "./srp"

func main() {
    bits := 2048
    pass := []byte("password string that's too long")
    i    := []byte("foouser")


    Ih, salt, v, err := srp.Verifier(i, pass, bits)
    if err != nil {
        panic(err)
    }

    // Store Ih, salt, v, bits in the DB
    Ih = Ih
    //fmt.Printf("bits=%d, I=%x\n  salt=%x\n  v=%x\n", bits, Ih, salt, v)

    c, err := srp.NewClient(i, pass, bits)

    if  err != nil {
        panic(err)
    }

    creds := c.Creds()
    //fmt.Printf("Client->Server: %s\n\n", creds)

    // send: C->S: creds


    // Begin the server by parsing the client creds

    I, A, err := srp.ServerBegin(creds)
    if err != nil {
        panic(err)
    }

    // Now, pretend to lookup the user db using "I" as the key and
    // fetch salt, verifier etc.

    s, err := srp.NewServer(I, salt, v, A, bits)
    if err != nil {
        panic(err)
    }

    // Generate the credentials to send to client
    creds = s.Credentials()

    //fmt.Printf("Server->Client: %s\n\n", creds)

    // Receive S->C: creds
    // Generate the mutual authenticator
    m1, err := c.Generate(creds)
    if err != nil {
        panic(err)
    }


    // Send the mutual authenticator to server

    // Receive the proof of authentication from server
    proof, err := s.ClientOk(m1)
    if err != nil {
        panic(err)
    }

    // Send proof to the client


    // Verify the server's proof
    err = c.ServerOk(proof)
    if err != nil {
        panic(err)
    }


    // Now, we have successfully authenticated the client to the
    // server and vice versa.


    kc := c.RawKey()
    ks := s.RawKey()

    if 1 != subtle.ConstantTimeCompare(kc, ks) {
        panic("Keys are different!")
    }

    fmt.Printf("Client Key: %x\nServer Key: %x\n", kc, ks)
}

// EOF
