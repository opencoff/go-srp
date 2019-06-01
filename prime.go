// prime.go - Generate safe primes
//
// Copyright 2013-2017 Sudhi Herle <sudhi.herle-at-gmail-dot-com>
//
// This code is largely simplified copy of crypto/rand/util.go; and thus, this file is licensed
// under the same terms as golang.

package srp

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// safePrime generates a safe prime; i.e., a prime 'p' such that 2p+1 is also prime.
func safePrime(bits int) (*big.Int, error) {

	z := 0

	p2 := new(big.Int)
	for {
		p, err := prime(bits)
		if err != nil {
			return nil, err
		}
		z++

		// (p-1)/2 should also be prime
		p2.Rsh(p, 1)
		if p2.ProbablyPrime(20) {
			return p, nil
		}
	}

	// never reached
	return nil, nil
}

// Prime returns a number, p, of the given size, such that p is prime
// with high probability.
// Prime will return error for any error returned by rand.Read or if bits < 2.
func prime(bits int) (p *big.Int, err error) {
	if bits < 2 {
		err = errors.New("crypto/rand: prime size must be at least 2-bit")
		return
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	}

	bytes := make([]byte, (bits+7)/8)
	p = new(big.Int)

	for {
		_, err = io.ReadFull(rand.Reader, bytes)
		if err != nil {
			return nil, err
		}

		// Clear bits in the first byte to make sure the candidate has a size <= bits.
		bytes[0] &= uint8(int(1<<b) - 1)

		// Don't let the value be too small, i.e, set the most significant two bits.
		// Setting the top two bits, rather than just the top bit,
		// means that when two of these values are multiplied together,
		// the result isn't ever one bit short.
		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if len(bytes) > 1 {
				bytes[1] |= 0x80
			}
		}

		// Set the first two bits since we will be looking for safe primes.
		// * if p is prime, we want (p-1)/2 to also be prime.
		// * (p-1)/2 is p >> 1
		// * and setting bit 1 guarantees that (p-1)/2 will be odd.
		bytes[len(bytes)-1] |= 3
		p.SetBytes(bytes)
		if p.ProbablyPrime(20) && p.BitLen() == bits {
			return
		}
	}
}

// Return true if g is a generator for safe prime p
//
// Stinson and Paterson (Th. 6.8 pp 196):
//   If p > 2 is a prime and g is in Zp*, then
//   g is a generator modulo p iff g ^ (p-1)/q != 1 (mod p)
//   for all primes q such that q divides (p-1).
//
// Code added as a result of bug pointed out by Dharmalingam G. (May 2019)
func isGenerator(g, p *big.Int) bool {
	p1 := big.NewInt(0).Sub(p, one)
	q := big.NewInt(0).Rsh(p1, 1) // q = p-1/2 = ((p-1) >> 1)

	// p is a safe prime. i.e., it is of the form 2q+1 where q is prime.
	// p-1 = 2q, where q is a prime.
	//
	// All factors that divide p-1 are: {2, q, 2q}
	//
	// So, our check really comes down to:
	//   1) g ^ (p1/2q) != 1 mod p
	//		=> g ^ (2q/2q) != 1 mod p
	//		=> g != 1 mod p
	//	    Trivial case. We ignore this.
	//
	//   2) g ^ (p1/2) != 1 mod p
	//      => g ^ (2q/2) != 1 mod p
	//      => g ^ q != 1 mod p
	//
	//   3) g ^ (p1/q) != 1 mod p
	//      => g ^ (2q/q) != 1 mod p
	//      => g ^ 2 != 1 mod p
	//

	// g ^ 2 mod p
	if !ok(g, big.NewInt(0).Lsh(one, 1), p) {
		return false
	}

	// g ^ q mod p
	if !ok(g, q, p) {
		return false
	}

	return true
}

func ok(g, x *big.Int, p *big.Int) bool {
	z := big.NewInt(0).Exp(g, x, p)
	if z.Cmp(one) != 0 { // the expmod should NOT be 1
		return true
	}
	return false
}
