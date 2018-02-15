Standalone SRP-6a implementation in go-lang
===========================================

This is a standalone implementation of SRP in golang. It uses the go
standard libraries and has no other external dependencies. This
library can be used by SRP clients or servers.

SRP is a protocol to authenticate a user and derive safe session
keys. It is the latest in the category of "strong authentication
protocols".

SRP is documented here: http://srp.stanford.edu/doc.html

Setting up the Verifiers on the Server
--------------------------------------
In order to authenticate and derive session keys, verifiers must be
stored in a non-volatile medium on the server. The verifiers are
generated once when a *user* is created on the server.

The Client is the entity where the user enters their password and
wishes to be authenticated with a SRP server. The communication
between client and server can happen in clear text - SRP is immune
to man in the middle attacks.

The client and server need to agree a-priori on the number of bits
to be used for the common "safe prime". It is acceptable to use 2048
or 4096 for this value. Each verifier can have a different number of
safe prime bits - but it must be recorded along with the verifier.
Every authentication attempt must use the same bit-size for the safe
prime previously recorded for that verifier. E.g.,::


    Ih, salt, v, err := srp.Verifier(username, password, Safe_prime_bits)

    // Now store Ih, salt, v and possibly Safe_prime_bits in non-volatile storage


Note that Ih is the hashed identity string for username.

Authentication attempt from the Client
--------------------------------------
The client performs the following sequence of steps to authenticate and derive session keys::

    c, err := srp.NewClient(username, password, Safe_prime_bits)

    if err != nil {
        panic(err)
    }

    creds := c.Credentials()
         
    // send the credentials to the server. It is already in ASCII string form.

    // Receive the server credentials into 'server_creds'
    // it is assumed that there is some network communication that happens
    // to get this string from the server

    // Now, generate a mutual authenticator to be sent to the server
    auth, err := c.Generate(server_creds)
    if err != nil {
        panic(err)
    }

    // Send the mutual authenticator to the server and receive "proof" that
    // the server too computed the same result.
        
    // Verify that we too have derived the same proof of authentication and
    // session keys
    err = c.ServerOk(proof)
    if err != nil {
        panic(err)
    }

    // Generate session key
     
    rawkey := c.RawKey()


Authenticating a Client on the Server
-------------------------------------

On the server, the authentication attempt begins after receiving the
initial user credentials. This is used to lookup the stored verifier
and other bits.::


    // Assume that we received the user credentials via the network into 'creds'


    // Parse the user info and authenticator from the 'creds' string
    I, A, err := srp.ServerBegin(creds)


    // Use 'I' to lookup the user in some non-volatile DB and obtain
    // previously stored verifier 'v' and 'salt' for that user.

    // Begin a new client-server SRP session
    s, err := srp.NewServer(I, salt, v, A, Safe_prime_bits)
    if err != nil {
        panic(err)
    }

    // Generate server credentials to send to the user and wait for the
    // mutual authenticator to arrive
    s_creds := s.Credentials()

    // Now send 's_creds' to the client and receive 'm_auth' from the client

    // Authenticate user and generate proof of authentication
    proof, err := s.ClientOk(m_auth)
    if err != nil {
         panic("Authentication failed")
    }

    // Auth succeeded, derive session key
    rawkey := s.RawKey()


Building SRP
------------
There is an example program that shows you the API usage (documented
above).::

    $ mkdir srp-example && cd srp-example
    $ GOPATH=$PWD go get   github.com/opencoff/go-srp/srp
    $ GOPATH=$PWD go test  github.com/opencoff/go-srp/srp

Finally, build the example program::

    $ GOPATH=$PWD go build github.com/opencoff/go-srp/example
    $ ./example

The example program outputs the raw-key from the client & server's
perspective (they should be identical).

Using the library in your program::

    $ go get github.com/opencoff/go-srp/srp

And in your program - as the following import path::

    import "github.com/opencoff/go-srp/srp"


Other Notes
-----------

* The client and server both derive the same value for `RawKey()`. This is
  the crux of the SRP protocol. Treat this as a "master key".

* It is not advisable to use the RawKey() for encryption purposes. It is
  better to derive a separate key for each direction (client->server
  and server->client). e.g., ::

      c2s_k = KDF(rawkey, counter, "C2S")
      s2s_k = KDF(rawkey, counter, "S2C")

* KDF above can be a reputable key derivation function such as PBKDF2 or
  Scrypt.  The "counter" is incremented every time you derive a new key. 

* *I am not a cryptographer*. Please consult your favorite crypto book for
  deriving encryption keys from a master key. Here is a example KDF
  using ``scrypt``::

    import "golang.org/x/crypto/scrypt"

    // Safe values for Scrypt() parameters
    const _N int = 65536
    const _r int = 1024
    const _p int = 64
        
    // Kdf derives a 'sz' byte key for use 'usage'
    func Kdf(key []byte, salt []byte, usage string, sz int) []byte {

        u0 := []byte(usage)
        pw := append(key, u0...)
        k, _ := scrypt.Key(pw, salt, _N, _r, _p, sz)
        return k
    }

* Argon_ is the new state of the art (2018) key derivation algorithm.
  The Argon2id variant is resistant to timing, side-channel and Time-memory
  tradeoff attacks. Here is an example using the Argon2id variant::

    import (
        "runtime"
        "golang.org/x/crypto/argon2"
    )

    // safe values for IDKey() borrowed from libsodium
    const _Time uint32 = 3
    const _Mem  uint32 = 256 * 1048576  // 256 MB

    // Kdf derives a 'sz' byte key for use 'usage'
    func Kdf(key, salt []byte, usage string, sz int) []byte {
        u0 := []byte(usage)
        pw := append(key, u0...)

        return argon2.IDKey(pw, salt, _Time, _Mem, runtime.NumCPU(), uint32(sz))
    }

.. _Argon: https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03

.. vim: ft=rst:sw=4:ts=4:tw=72:
