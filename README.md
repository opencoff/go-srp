# Standalone SRP-6a implementation in go-lang

[![GoDoc](https://godoc.org/github.com/opencoff/go-srp?status.svg)](https://godoc.org/github.com/opencoff/go-srp) 
[![Go Report
Card](https://goreportcard.com/badge/github.com/opencoff/go-srp)](https://goreportcard.com/report/github.com/opencoff/go-srp) 
This is a standalone implementation of SRP in golang. It uses the go
standard libraries and has no other external dependencies. This library
can be used by SRP clients or servers.

SRP is a protocol to authenticate a user and derive safe session keys.
It is the latest in the category of \"strong authentication protocols\".

SRP is documented here: <http://srp.stanford.edu/doc.html>. Briefly,

### Conventions

    N    A large safe prime (N = 2q+1, where q is prime)
       All arithmetic is done modulo N.
    g    A generator modulo N
    k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    s    User's salt
    I    Username
    p    Cleartext Password
    H()  One-way hash function
    ^    (Modular) Exponentiation
    u    Random scrambling parameter
    a,b  Secret ephemeral values
    A,B  Public ephemeral values
    x    Private key (derived from p and s)
    v    Password verifier

The host stores passwords using the following formula:

    s = randomsalt()          (same length as N)
    I = H(I)
    p = H(p)                  (hash/expand I & p)
    t = H(I, ":", p)
    x = H(s, t)
    v = g^x                   (computes password verifier)

The host then keeps {I, s, v} in its password database.

The authentication protocol itself goes as follows:

    Client                       Server
    --------------               ----------------
    un, pw = < user input >
    I = H(un)
    p = H(pw)
    a = random()
    A = g^a % N
                I, A -->
                              s, v = lookup(I)
                              b = random()
                              B = (kv + g^b) % N
                              u = H(A, B)
                              S = ((A * v^u) ^ b) % N
                              K = H(S)
                              M' = H(K, A, B, I, s, N, g)
                 <-- s, B
    u = H(A, B)
    x = H(s, p)
    S = ((B - k (g^x)) ^ (a + ux)) % N
    K = H(S)
    M = H(K, A, B, I, s, N, g)

                M -->
                              M must be equal to M'
                              Z = H(M, K)
                <-- Z

    Z' = H(M, K)
    Z' must equal Z

When the server receives `<I, A>`, it can compute everything: shared key
and proof-of-generation `M'`. The shared key is `K`.

To verify that the client has generated the same key `K`, the client sends
`M` -- a hash of all the data it has and it received from the server. To
validate that the server also has the same value, it requires the server to send
its own proof. In the SRP paper, the authors use:

    M = H(H(N) xor H(g), H(I), s, A, B, K)
    M' = H(A, M, K)

We use a simpler construction:

    M = H(K, A, B, I, s, N, g)
    M' = H(M, K)

The two parties also employ the following safeguards:

 1. The user will abort if he receives `B == 0 (mod N) or u == 0`.
 2. The host will abort if it detects that `A == 0 (mod N)`.
 3. The user must show his proof of K first. If the server detects that the
    user\'s proof is incorrect, it must abort without showing its own proof of K.

In our implementation:

- The standard hash function is Blake2b-256; this can be changed by choosing an
  appropriate hash from `crypto`:
  ```go

       s, err := srp.NewWithHash(crypto.SHA256, 4096)
  ```

- We pad `g`, `A`, `B` with leading zeroes to make them same sized as the
  prime-field (as in RFC 5054). See below:

  ```
       H = Blake2b_256()
       k = H(N, pad(g))
       I = H(username)
       p = H(password)
       x = H(salt, I, p)
       u = H(pad(A), pad(B)
  ```

## Setting up the Verifiers on the Server
In order to authenticate and derive session keys, verifiers must be
stored in a non-volatile medium on the server. The client provides the
prime-field size, username and password when creating the verifier. The
server stores the triple in a non-volatile medium. The verifiers are
generated once when a *user* is created on the server.

The Client is the entity where the user enters their password and wishes
to be authenticated with a SRP server. The communication between client
and server can happen in clear text - SRP is immune to man in the middle
attacks.

Depending on the resources available on a given client, it can choose a
small or large prime-field; but once chosen it is recorded on the server
until a new verifier is generated.

For example, a client will do:

```go

    s, err := srp.New(n_bits)

    v, err := s.Verifier(username, password)
    id, verif := v.Encode()

    // Now, store 'id', 'verif' in non-volatile storage such that 'verif' can be
    // retrieved by providing 'id'.
```

Note that `id` is the hashed identity string for username.

A client may wish to change the default hash function to something else. e.g.,::

```go

    s, err := srp.NewWithHash(crypto.SHA256, n_bits)

    v, err := s.Verifier(username, password)
    id, verif := v.Encode()
```

## Authentication attempt from the Client
The client performs the following sequence of steps to authenticate and
derive session keys:

```go
    
    s, err := srp.New(n_bits)

    c, err := s.NewClient(user, pass)
    creds := c.Credentials()

    // 1. send the credentials to the server. It is already in ASCII string form; this
    //    is essentially the encoded form of identity and a random public key.

    // 2. Receive the server credentials into 'server_creds'; this is the server 
    //    public key and random salt generated when the verifier was created.

    // It is assumed that there is some network communication that happens
    // to get this string from the server.

    // Now, generate a mutual authenticator to be sent to the server
    auth, err := c.Generate(server_creds)

    // 3. Send the mutual authenticator to the server
    // 4. receive "proof" that the server too computed the same result.

    // Verify that the server actually did what it claims
    if !c.ServerOk(proof) {
        panic("authentication failed")
    }

    // Generate session key
    rawkey := c.RawKey()
```

## Authenticating a Client on the Server
On the server, the authentication attempt begins after receiving the
initial user credentials. This is used to lookup the stored verifier and
other bits.:

```go

    // Assume that we received the user credentials via the network into 'creds'


    // Parse the user info and authenticator from the 'creds' string
    id, A, err := srp.ServerBegin(creds)

    // Use 'id' to lookup the user in some non-volatile DB and obtain
    // previously stored *encoded* verifier 'v'.
    verifier := db.Lookup(id)


    // Create an SRP instance and Verifier instance from the stored data.
    s, v, err := srp.MakeSRPVerifier(verifier)

    // Begin a new client-server SRP session using the verifier and received
    // public key.
    srv, err := s.NewServer(v, A)

    // Generate server credentials to send to the user
    s_creds := srv.Credentials()

    // 1. send 's_creds' to the client
    // 2. receive 'm_auth' from the client

    // Authenticate user and generate mutual proof of authentication
    proof, ok := srv.ClientOk(m_auth)
    if ok != nil {
         panic("Authentication failed")
    }

    // 3. Send proof to client

    // Auth succeeded, derive session key
    rawkey := s.RawKey()
```

## Building SRP

There is an example program that shows you the API usage (documented
above).:

```sh
    $ mkdir srp-example && cd srp-example
    $ GOPATH=$PWD go get   github.com/opencoff/go-srp
    $ GOPATH=$PWD go test  github.com/opencoff/go-srp
```

Finally, build the example program:

```sh
    $ GOPATH=$PWD go build github.com/opencoff/go-srp/example
    $ ./example
```

The example program outputs the raw-key from the client & server\'s
perspective (they should be identical).

Using the library in your program:

```sh
    $ go get github.com/opencoff/go-srp
```

And in your program - as the following import path:

```go

    import "github.com/opencoff/go-srp"
```

Other Notes
-----------

-   The client and server both derive the same value for RawKey(). This
    is the crux of the SRP protocol. Treat this as a \"master key\".
-   It is not advisable to use the RawKey() for encryption purposes. It
    is better to derive a separate key for each direction
    (client-\>server and server-\>client). e.g.,:

    ```go
        c2s_k = KDF(rawkey, counter, "C2S")
        s2s_k = KDF(rawkey, counter, "S2C")
    ```

-   KDF above can be a reputable key derivation function such as PBKDF2
    or Scrypt. The \"counter\" is incremented every time you derive a
    new key.

-   *I am not a cryptographer*. Please consult your favorite crypto book
    for deriving encryption keys from a master key. Here is a example
    KDF using `scrypt`:

    ```go
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
    ```

-   [Argon](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03) is
    the new state of the art (2018) key derivation algorithm. The
    `Argon2id` variant is resistant to timing, side-channel and
    Time-memory tradeoff attacks. Here is an example using the `Argon2id`
    variant:

    ```go
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
    ```

