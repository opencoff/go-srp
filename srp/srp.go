//
// Copyright 2013-2014 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
// License: MIT
//
// Implementation of SRP_.  It requires a cryptographically strong
// random number generator.
// 
// This implementation is accurate as of Aug 2012 edition of the SRP_
// specification.
// 
// Conventions
// -----------
//   N    A large safe prime (N = 2q+1, where q is prime)
//        All arithmetic is done modulo N.
//   g    A generator modulo N
//   k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
//   s    User's salt
//   I    Username
//   p    Cleartext Password
//   H()  One-way hash function
//   ^    (Modular) Exponentiation
//   u    Random scrambling parameter
//   a,b  Secret ephemeral values
//   A,B  Public ephemeral values
//   x    Private key (derived from p and s)
//   v    Password verifier
// 
// The host stores passwords using the following formula:
// 
//   x = H(s, p)               (s is chosen randomly)
//   v = g^x                   (computes password verifier)
// 
// The host then keeps {I, s, v} in its password database.
// 
// The authentication protocol itself goes as follows:
// 
//         User -> Host:  I, A = g^a          (identifies self, a = random number)
//         Host -> User:  s, B = kv + g^b     (sends salt, b = random number)
// 
//         Both:  u = H(A, B)
// 
//         User:  x = H(s, p)                 (user enters password)
//         User:  S = (B - kg^x) ^ (a + ux)   (computes session key)
//         User:  K = H(S)
// 
//         Host:  S = (Av^u) ^ b              (computes session key)
//         Host:  K = H(S)
// 
// Now the two parties have a shared, strong session key K.
// To complete authentication, they need to prove to each other that
// their keys match. One possible way:
// 
// User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
// Host -> User:  H(A, M, K)
// 
// The two parties also employ the following safeguards:
// 
//  1. The user will abort if he receives B == 0 (mod N) or u == 0.
//  2. The host will abort if it detects that A == 0 (mod N).
//  3. The user must show his proof of K first. If the server detects that the
//     user's proof is incorrect, it must abort without showing its own proof of K. 
// 
// In this implementation::
// 
//     H  = SHA256()
//     k  = H(N, g)
//     x  = HMAC-SHA(s, I, P)
//     I  = anonymized form of user identity (SHA256 of value sent by client)
// 
// There are two verifiers that are computed:
//     M1 = HMAC-SHA(K, H(A, b, I, s, N, g)) - sent by the client to the server
//     M2 = H(K, M1) - sent by the server to the client
// 
// This convention guarantees that both parties can mutually conclude
// that they have generated an identical key.
// 
// 
// .. _SRP: http://srp.stanford.edu/
// 

package srp

import (
    "math/big"
    "fmt"
    "crypto/hmac"
    "crypto/sha256"
    "io"
    "strings"
)

import CR "crypto/rand"
import MR "math/rand"


// Map of bits to <g, N> tuple
var pflist_str = map[int] [2]string  {1024 : {"2", "0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3"},
        1536 : {"2", "0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB"},
        2048 : {"2", "0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"},
        3072 : {"2", "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"},
        4096 : {"5", "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF"},
        6144 : {"5", "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF"},
        8192 : {"5", "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF"},
        }



// XXX Use blake2 or keccak in the future
var mac = sha256.New

type prime_field struct {
    g  *big.Int
    N  *big.Int
}

// prime field list - mapped by bit size
var pflist map[int] prime_field



// build the database of prime fields and generators
func init() {

    pflist = make(map[int] prime_field)

    for bits, arr := range pflist_str {
        g, ok0 := big.NewInt(0).SetString(arr[0], 10)
        n, ok1 := big.NewInt(0).SetString(arr[1], 0)

        if !ok0 {
            s := fmt.Sprintf("srp init: Can't parse string %s", arr[0])
            panic(s)
        }

        if !ok1 {
            s := fmt.Sprintf("srp init: Can't parse string %s", arr[1])
            panic(s)
        }

        pflist[bits] = prime_field{g:g, N:n}
    }
}


// hash byte stream and return as bytes
func hashbyte(a ...[]byte) []byte {
    h := mac()
    for _, z := range a {
        h.Write(z)
    }
    return h.Sum(nil)
}


// hmac a number of byte streams
func _hmac(key []byte, a ...[]byte) []byte {
    s := sha256.New
    h := hmac.New(s, key)

    for _, w := range a {
        h.Write(w)
    }

    return h.Sum(nil)
}


// hash a number of byte strings and return the resulting hash as
// bigint
func hashint(a ...[]byte) *big.Int {
    i := big.NewInt(0)
    b := hashbyte(a...)
    i.SetBytes(b)
    return i
}


// hash a number of byte strings and return the result as a human
// readable string
func hashhex(a ...[]byte) string {
    h := hashbyte(a...)
    s := fmt.Sprintf("%x", h)
    return s
}



// hmac a number of byte strings and return the resulting hash as
// bigint
func hmacint(key []byte, a ...[]byte) *big.Int {
    h := _hmac(key, a...)
    b := big.NewInt(0).SetBytes(h)
    return b
}

// Return n bytes of random  bytes. Uses cryptographically strong
// random generator
func randbytes(n int) []byte {
    b := make([]byte, n)
    _, err := io.ReadFull(CR.Reader, b)
    if err != nil {
        panic("Random source is broken!")
    }
    return b
}


// Generate and return a bigInt 'bits' bits in length
func randlong(bits int) *big.Int {
    n := bits / 8
    if 0 == bits % 8 {
        n += 1
    }
    b := randbytes(n)
    r := big.NewInt(0).SetBytes(b)
    return r
}


// Generate a password veririer for user I and passphrase p
// Return tuple containing hashed identity, salt, verifier. Caller
// is expected to store the tuple in some persistent DB
func Verifier(I, p []byte, bits int) (Ih, salt, v []byte, err error) {
    pf, ok := pflist[bits]
    if 0 == big.NewInt(0).Cmp(pf.N) || !ok {
        err = fmt.Errorf("Invalid bits: %d", bits)
        return
    }

    i := hashbyte(I)
    s := randbytes((bits/2)/8)
    x := hmacint(p, s, i)

    r := big.NewInt(0).Exp(pf.g, x, pf.N)

    salt = s
    Ih   = i
    v    = r.Bytes()

    return
}

// Represents an SRP Client instance
type Client struct {
    g  *big.Int
    N  *big.Int
    i  []byte
    p  []byte
    a  *big.Int
    A  *big.Int
    k  *big.Int

    K []byte
    M []byte

}


// Client SRP class constructor
func NewClient(I, p []byte, bits int) (c *Client, err error) {
    c = new(Client)
    err = c.init(I, p, bits)

    return
}

func (c *Client) init(I, p []byte, bits int) (err error) {
    pf, ok := pflist[bits]
    if 0 == big.NewInt(0).Cmp(pf.N) || !ok {
        err = fmt.Errorf("Invalid bits: %d", bits)
        return
    }

    // g, N := field(bits)
    // a := generate random a
    // A := g^a % N
    // k := H(N, g)

    c.g = pf.g
    c.N = pf.N
    c.i = hashbyte(I)
    c.p = p
    c.a = randlong(bits)
    c.A = big.NewInt(0).Exp(pf.g, c.a, pf.N)
    c.k = hashint(c.N.Bytes(), c.g.Bytes())

    return nil
}


// Return client public credentials to send to server
// Send <I, A> to server
func (c *Client) Creds() string {
    s := fmt.Sprintf("%x:0x%x", c.i, c.A.Bytes())
    return s
}

// Validate the server public credentials and generate session key
// Return the mutual authenticator
// - Get <s, B> from server
// - calculate S from a, s, B
func (c *Client) Generate(srv string) (auth string, err error) {
    v := strings.Split(srv, ":")
    if len(v) != 2 {
        err = fmt.Errorf("Invalid server public key")
        return
    }

    var s []byte

    _, err  = fmt.Sscanf(v[0], "%x", &s)
    B, ok1 := big.NewInt(0).SetString(v[1], 0)

    if err != nil {
        err = fmt.Errorf("Invalid server public key s=%s", v[0])
        return
    }

    if !ok1 {
        err = fmt.Errorf("Invalid server public key B=%s", v[1])
        return
    }

    zero := big.NewInt(0)
    z := big.NewInt(0).Mod(B, c.N)
    if zero.Cmp(z) == 0 {
        err = fmt.Errorf("Invalid server public key B=%x", B)
        return
    }

    u := hashint(c.A.Bytes(), B.Bytes())
    if u.Cmp(zero) == 0 {
        err = fmt.Errorf("Invalid server public key u")
        return
    }


    // S := (B - kg^x) ^ (a + u * x) % N


    x  := hmacint(c.p, s, c.i)

    t0 := big.NewInt(0).Exp(c.g, x, c.N)
    t0  = t0.Mul(t0, c.k)

    t1 := big.NewInt(0).Sub(B, t0)
    t2 := big.NewInt(0).Add(c.a, big.NewInt(0).Mul(u, x))
    S  := big.NewInt(0).Exp(t1, t2, c.N)

    c.K = hashbyte(S.Bytes())

    c.M = _hmac(c.K, c.A.Bytes(), B.Bytes(), c.i, s, c.N.Bytes(), c.g.Bytes())

    return fmt.Sprintf("%x", c.M), nil
}


// Take a 'proof' offered by the server and verify that it is valid.
// i.e., we should compute the same hmac() on M that the server did.
func (c *Client) ServerOk(proof string) error {
    h   := _hmac(c.K, c.M)
    myh := fmt.Sprintf("%x", h)

    if ! streq(myh, proof) {
        return fmt.Errorf("Server failed to generate same password")
    }

    return nil
}


// Return the raw key computed as part of the protocol
func (c *Client) RawKey() []byte {
    return c.K
}


// Derive a session key from the raw key. THis is what all the users
// of the API should call.
func (c * Client) SessionKey() []byte {
    return SessionKey(c.K, 32)
}


// Stringfy
func (c *Client) String() string {
    return fmt.Sprintf("<client> g=%d, N=%x\n I=%x\n A=%x\n K=%x\n",
           c.g, c.N, c.i, c.A, c.K)
}

// Represents an SRP Server instance
type Server struct {
    g  *big.Int
    N  *big.Int
    i  []byte
    s  []byte
    v  *big.Int
    B  *big.Int

    K []byte
    M []byte

}



// Begin the server processing by parsing the credentials sent by
// the client.
// The caller is expected to use 'I' to lookup some database and
// find the verifier, salt and other user specific parameters.
func ServerBegin(creds string) (I []byte, A *big.Int, err error) {
    v := strings.Split(creds, ":")
    if len(v) != 2 {
        err = fmt.Errorf("Invalid client public key")
        return
    }

    A, ok := big.NewInt(0).SetString(v[1], 0)
    if !ok {
        err = fmt.Errorf("Invalid client public key A")
        return
    }

    _, err = fmt.Sscanf(v[0], "%x", &I)
    if err != nil {
        return
    }

    return
}



// Constructor for the server type
func NewServer(I, s, v []byte, A *big.Int, bits int) (c *Server, err error) {
    c = new(Server)
    err = c.init(I, s, v, A, bits)

    return
}


// Private method to initialize the Server SRP class
func (c *Server) init(I, s, v []byte, A *big.Int, bits int) (err error) {
    pf, ok := pflist[bits]
    if !ok {
        err = fmt.Errorf("Invalid bits: %d", bits)
        return
    }

    c.v = big.NewInt(0).SetBytes(v)

    zero := big.NewInt(0)

    // g, N := field(bits)
    // b := generate random b
    // k := H(N, g)
    // B := kv + g^b
    // u := H(A, B)
    // S := (Av^u) ^ b
    // K := H(S)

    c.g = pf.g
    c.N = pf.N
    c.s = s
    c.i = I


    b  := randlong(bits)
    k  := hashint(c.N.Bytes(), c.g.Bytes())
    t0 := big.NewInt(0).Mul(k, c.v)
    t1 := big.NewInt(0).Add(t0, big.NewInt(0).Exp(c.g, b, c.N))
    B  := t1

    u  := hashint(A.Bytes(), B.Bytes())
    if u.Cmp(zero) == 0 {
        err = fmt.Errorf("Invalid server public key u")
        return
    }

    t0 = big.NewInt(0).Mul(A, big.NewInt(0).Exp(c.v, u, c.N))
    S := big.NewInt(0).Exp(t0, b, c.N)

    c.B = B
    c.K = hashbyte(S.Bytes())
    c.M = _hmac(c.K, A.Bytes(), B.Bytes(), I, s, c.N.Bytes(), c.g.Bytes())

    return nil
}


// Return the server credentials (s,B)  in a network portable format.
func (c* Server) Credentials() string {
    return fmt.Sprintf("%x:0x%x", c.s, c.B.Bytes())
}


// Verify that the client has generated the same password as the
// server and return proof that the server too has done the same.
func (c* Server) ClientOk(m string) (proof string, err error) {
    mym := fmt.Sprintf("%x", c.M)
    if ! streq(mym, m) {
        err = fmt.Errorf("Client failed to generate same password")
        return
    }

    h := _hmac(c.K, c.M)
    proof = fmt.Sprintf("%x", h)
    return proof, nil
}


// Return the raw key negotiated as part of the SRP
func (c *Server) RawKey() []byte {
    return c.K
}

// Return a session key based on authenticated key.
// This is the method all users of the API should use.
func (c * Server) SessionKey() []byte {
    return SessionKey(c.K, 32)
}


// Stringify the server parameters
func (c *Server) String() string {
    return fmt.Sprintf("<server> g=%d, N=%x\n I=%x\n s=%x\n B=%x\n K=%x\n",
           c.g, c.N, c.i, c.s, c.B, c.K)
}


// Generate a session key from the raw key
// XXX Use scrypt in the future
func SessionKey(rawkey []byte, keylen int) []byte {
    if 0 == keylen {
        keylen = 32
    }

    // XXX This number should be parametrized somehow to account for
    //     CPU and memory speed growth.
    r  := MR.Int31n(5000)
    sc := randbytes(keylen)
    return Pbkdf2(rawkey, sc, int(r), mac, keylen)
}


// Constant time string compare
func streq(a, b string) bool {
    m := len(a)
    n := len(b)

    if m != n {
        return false
    }

    var v uint8
    for i := 0; i < m; i ++ {
        v |= a[i] ^ b[i]
    }

    return v == 0
}


// - EOF -
