//
// Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
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
//   s = randomsalt()          (same length as N)
//   I = H(I)
//   p = H(p)                  (hash/expand I & p)
//   t = H(I, ":", p)
//   x = H(s, t)
//   v = g^x                   (computes password verifier)
//
// The host then keeps {I, s, v} in its password database.
//
// The authentication protocol itself goes as follows:
//
//  Client                       Server
//  --------------               ----------------
//  I, p = < user input >
//  I = H(I)
//  p = H(p)
//  a = random()
//  A = g^a % N
//                 I, A -->
//                               s, v = lookup(I)
//                               b = random()
//                               B = (kv + g^b) % N
//                               u = H(A, B)
//                               S = ((A * v^u) ^ b) % N
//                               K = H(S)
//                               M' = H(K, A, B, I, s, N, g)
//                  <-- s, B
//  u = H(A, B)
//  x = H(s, p)
//  S = ((B - k (g^x)) ^ (a + ux)) % N
//  K = H(S)
//  M = H(K, A, B, I, s, N, g)
//
//		    M -->
//				M must be equal to M'
//				Z = H(M, K)
//		    <-- Z
//  Z' = H(M, K)
//  Z' must equal Z
// -----------------------------------------------------------------
// When the server receives <I, A>, it can compute everything: shared key
// and proof-of-generation (M'). The shared key is "K".
//
// To verify that the client has generated the same key "K", the client sends
// "M" -- a hash of all the data it has and it received from the server. To
// validate that the server also has the same value, it requires the server to send
// its own proof. In the SRP paper [1], the authors use:
//     M = H(H(N) xor H(g), H(I), s, A, B, K)
//     M' = H(A, M, K)
//
// We use a simpler construction:
//     M = H(K, A, B, I, s, N, g)
//     M' = H(M, K)
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
//     H  = BLAKE2()
//     k  = H(N, g)
//     x  = H(s, I, P)
//     I  = anonymized form of user identity (BLAKE2 of value sent by client)
//     P  = hashed password (expands short passwords)
//     
//
// Per RFC-5054, we adopt the following padding convention:
//    k = H(N, pad(g))
//    u = H(pad(A), pad(B))
//
// References:
// -----------
// [1] http://srp.stanford.edu/design.html
// [2] http://srp.stanford.edu/
//

package srp

import (
	"crypto"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	CR "crypto/rand"

	_ "golang.org/x/crypto/blake2b"
)


// Map of bits to <g, N> tuple
const pflist_str = `1024:2:0xEEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3
1536:2:0x9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB
2048:2:0xAC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73
3072:2:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF
4096:5:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
6144:5:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF
8192:5:0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF`

type prime_field struct {
	g *big.Int
	N *big.Int
}

// prime field list - mapped by bit size
var pflist map[int]*prime_field

// build the database of prime fields and generators
func init() {

	pflist = make(map[int]*prime_field)
	lines := strings.Split(pflist_str, "\n")
	for _, s := range lines {
		v := strings.Split(s, ":")
		b := atoi(v[0])

		pf := &prime_field{
			g: atobi(v[1], 10),
			N: atobi(v[2], 0),
		}
		if 0 == big.NewInt(0).Cmp(pf.N) {
			panic(fmt.Sprintf("srp init: N (%s) is zero", v[2]))
		}
		pflist[b] = pf
	}
}

func atoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		panic(fmt.Sprintf("srp init: can't parse int %s", s))
	}
	return i
}

func atobi(s string, base int) *big.Int {
	i, ok := big.NewInt(0).SetString(s, base)
	if !ok {
		panic(fmt.Sprintf("srp init: can't parse bigint |%s|", s))
	}
	return i
}

// hash byte stream and return as bytes
func hashbyte(a ...[]byte) []byte {
	h := crypto.BLAKE2b_256.New()
	for _, z := range a {
		h.Write(z)
	}
	return h.Sum(nil)
}

// pad x to n bytes if needed
func pad(x *big.Int, n int) []byte {
	b := x.Bytes()
	if len(b) < n {
		z := n - len(b)
		p := make([]byte, n, n)
		for i := 0; i < z; i++ {
			p[i] = 0
		}

		copy(p[z:], b)
		b = p
	}
	return b
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
func randBigInt(bits int) *big.Int {
	n := bits / 8
	if 0 == bits%8 {
		n += 1
	}
	b := randbytes(n)
	r := big.NewInt(0).SetBytes(b)
	return r
}

// Verifier generates a password verifier for user I and passphrase p
// Return tuple containing hashed identity, salt, verifier. Caller
// is expected to store the tuple in some persistent DB
func Verifier(I, p []byte, bits int) (Ih, salt, v []byte, err error) {
	pf, ok := pflist[bits]
	if 0 == big.NewInt(0).Cmp(pf.N) || !ok {
		err = fmt.Errorf("Invalid bits: %d", bits)
		return
	}

	I = hashbyte(I)
	p = hashbyte(p)
	s := randbytes(bits/8)
	i := hashbyte(I, []byte(":"), p)
	x := hashint(s, i)
	r := big.NewInt(0).Exp(pf.g, x, pf.N)

	salt = s
	Ih = I
	v = r.Bytes()

	//fmt.Printf("Verifier %d:\n\tv=%x\n\tx=%x\n", bits, v, x)

	return
}

// Client represents an SRP client instance
type Client struct {
	g  *big.Int
	xN *big.Int
	n  int // number of bytes in N
	i  []byte
	p  []byte
	a  *big.Int
	xA *big.Int
	k  *big.Int

	xK []byte
	xM []byte
}

// NewClient constructs an SRP client instance
func NewClient(I, p []byte, bits int) (*Client, error) {
	pf, ok := pflist[bits]
	if !ok {
		return nil, fmt.Errorf("srp: no support for %d bit field", bits)
	}

	c := &Client{
		g: pf.g,
		xN: pf.N,
		n: bits / 8,
		i: hashbyte(I),
		p: hashbyte(p),
		a: randBigInt(bits),
	}


	c.xA = big.NewInt(0).Exp(pf.g, c.a, pf.N)
	c.k = hashint(c.xN.Bytes(), pad(c.g, c.n))
	//fmt.Printf("Client %d:\n\tA=%x\n\tk=%x", bits, c.xA, c.k)
	return c, nil
}

// Credentials returns client public credentials to send to server
// Send <I, A> to server
func (c *Client) Credentials() string {
	s0 := hex.EncodeToString(c.i)
	s1 := hex.EncodeToString(c.xA.Bytes())
	return s0 + ":" + s1
}

// Generate validates the server public credentials and generate session key
// Return the mutual authenticator
// - Get <s, B> from server
// - calculate S from a, s, B
// NB: We don't send leak any information in error messages.
func (c *Client) Generate(srv string) (string, error) {
	v := strings.Split(srv, ":")
	if len(v) != 2 {
		return "", fmt.Errorf("invalid server public key")
	}

	s, err := hex.DecodeString(v[0])
	if err != nil {
		return "", fmt.Errorf("invalid server public key")
	}

	B, ok1 := big.NewInt(0).SetString(v[1], 16)
	if !ok1 {
		return "", fmt.Errorf("invalid server public key")
	}

	zero := big.NewInt(0)
	z := big.NewInt(0).Mod(B, c.xN)
	if zero.Cmp(z) == 0 {
		return "", fmt.Errorf("invalid server public key")
	}

	u := hashint(pad(c.xA, c.n), pad(B, c.n))
	if u.Cmp(zero) == 0 {
		return "", fmt.Errorf("invalid server public key")
	}

	// S := ((B - kg^x) ^ (a + ux)) % N

	i := hashbyte(c.i, []byte(":"), c.p)
	x := hashint(s, i)

	t0 := big.NewInt(0).Exp(c.g, x, c.xN)
	t0 = t0.Mul(t0, c.k)

	t1 := big.NewInt(0).Sub(B, t0)
	t2 := big.NewInt(0).Add(c.a, big.NewInt(0).Mul(u, x))
	S := big.NewInt(0).Exp(t1, t2, c.xN)

	c.xK = hashbyte(S.Bytes())
	c.xM = hashbyte(c.xK, c.xA.Bytes(), B.Bytes(), c.i, s, c.xN.Bytes(), c.g.Bytes())

	//fmt.Printf("Client %d:\n\tx=%x\n\tS=%x\n\tK=%x\n\tM=%x\n", c.n *8, x, S, c.xK, c.xM)

	return hex.EncodeToString(c.xM), nil
}

// ServerOk takes a 'proof' offered by the server and verifies that it is valid.
// i.e., we should compute the same hash() on M that the server did.
func (c *Client) ServerOk(proof string) error {
	h := hashbyte(c.xK, c.xM)
	myh := hex.EncodeToString(h)

	if subtle.ConstantTimeCompare([]byte(myh), []byte(proof)) != 1 {
		return fmt.Errorf("Server failed to generate same password")
	}

	return nil
}

// RawKey returns the raw key computed as part of the protocol
func (c *Client) RawKey() []byte {
	return c.xK
}

// String represents the client parameters as a string value
func (c *Client) String() string {
	return fmt.Sprintf("<client> g=%d, N=%x\n I=%x\n A=%x\n K=%x\n",
		c.g, c.xN, c.i, c.xA, c.xK)
}

// Server represents an SRP server instance
type Server struct {
	g  *big.Int
	xN *big.Int
	n  int // number of bytes in N
	i  []byte
	s  []byte
	v  *big.Int
	xB *big.Int

	xK []byte
	xM []byte
}

// ServerBegin begins the server processing by parsing the credentials sent by
// the client.
// The caller is expected to use 'I' to lookup some database and
// find the verifier, salt and other user specific parameters.
func ServerBegin(creds string) (I []byte, A *big.Int, err error) {
	v := strings.Split(creds, ":")
	if len(v) != 2 {
		err = fmt.Errorf("Invalid client public key")
		return
	}

	//fmt.Printf("v0: %s\nv1: %s\n", v[0], v[1])

	A, ok := big.NewInt(0).SetString(v[1], 16)
	if !ok {
		err = fmt.Errorf("Invalid client public key A")
		return
	}

	I, err = hex.DecodeString(v[0])
	return
}

// NewServer constructs a Server instance
func NewServer(I, salt, v []byte, A *big.Int, bits int) (*Server, error) {
	pf, ok := pflist[bits]
	if !ok {
		return nil, fmt.Errorf("srp: no support for %d bit field", bits)
	}

	s := &Server{
		g:  pf.g,
		xN: pf.N,
		s:  salt,
		i:  I,
		v:  big.NewInt(0).SetBytes(v),
		n:  bits / 8,
	}

	// g, N := field(bits)
	// b := generate random b
	// k := H(N, g)
	// B := kv + g^b
	// u := H(A, B)
	// S := (Av^u) ^ b
	// K := H(S)

	zero := big.NewInt(0)

	b := randBigInt(bits)
	k := hashint(s.xN.Bytes(), pad(s.g, s.n))
	t0 := big.NewInt(0).Mul(k, s.v)
	B := big.NewInt(0).Add(t0, big.NewInt(0).Exp(s.g, b, s.xN))

	u := hashint(pad(A, s.n), pad(B, s.n))
	if u.Cmp(zero) == 0 {
		return nil, fmt.Errorf("Invalid server public key u")
	}

	t0 = big.NewInt(0).Mul(A, big.NewInt(0).Exp(s.v, u, s.xN))
	S := big.NewInt(0).Exp(t0, b, s.xN)

	s.xB = B
	s.xK = hashbyte(S.Bytes())
	s.xM = hashbyte(s.xK, A.Bytes(), B.Bytes(), I, salt, s.xN.Bytes(), s.g.Bytes())

	//fmt.Printf("Server %d:\n\tv=%x\n\tk=%x\n\tA=%x\n\tS=%x\n\tK=%x\n\tM=%x\n", bits, v, k, A.Bytes(), S, s.xK, s.xM)

	return s, nil
}

// Credentials returns the server credentials (s,B) in a network portable
// format.
func (s *Server) Credentials() string {

	s0 := hex.EncodeToString(s.s)
	s1 := hex.EncodeToString(s.xB.Bytes())
	return s0 + ":" + s1
}

// ClientOk verifies that the client has generated the same password as the
// server and return proof that the server too has done the same.
func (s *Server) ClientOk(m string) (proof string, err error) {
	mym := hex.EncodeToString(s.xM)

	if subtle.ConstantTimeCompare([]byte(mym), []byte(m)) != 1 {
		return "", fmt.Errorf("Client failed to generate same password")
	}

	h := hashbyte(s.xK, s.xM)
	return hex.EncodeToString(h), nil
}

// RawKey returns the raw key negotiated as part of the SRP
func (s *Server) RawKey() []byte {
	return s.xK
}

// String represents the Server parameters as a string value
func (s *Server) String() string {
	return fmt.Sprintf("<server> g=%d, N=%x\n I=%x\n s=%x\n B=%x\n K=%x\n",
		s.g, s.xN, s.i, s.s, s.xB, s.xK)
}

// - EOF -
