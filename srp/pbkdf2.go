package srp

import (
    "crypto/hmac"
    "crypto/rand"
    "crypto/sha1"
    "crypto/subtle"
    "hash"
    "io"
)

// Calculate password hash with PKCS#5 PBKDF2 method using the given hash function as HMAC.
func Pbkdf2(password []byte, salt []byte, iterations int, hash func() hash.Hash, outlen int) (out []byte) {
    out = make([]byte, outlen)
    hashSize := hash().Size()
    ibuf := make([]byte, 4)
    block := 1
    p := out
    for outlen > 0 {
        clen := outlen
        if clen > hashSize {
            clen = hashSize
        }

        ibuf[0] = byte((block >> 24) & 0xff)
        ibuf[1] = byte((block >> 16) & 0xff)
        ibuf[2] = byte((block >> 8) & 0xff)
        ibuf[3] = byte((block) & 0xff)

        h := hmac.New(hash, password)
        h.Write(salt)
        h.Write(ibuf)
        tmp := h.Sum(nil)
        for i := 0; i < clen; i++ {
            p[i] = tmp[i]
        }

        for j := 1; j < iterations; j++ {
            h.Reset()
            h.Write(tmp)
            tmp = h.Sum(nil)
            for k := 0; k < clen; k++ {
                p[k] ^= tmp[k]
            }
        }
        outlen -= clen
        block++
        p = p[clen:]
    }
    return
}

type PasswordHash struct {
    Salt []byte
    Hash []byte
}

// Call Pbkdf2 password hash with reasonable defaults (9999 iterations + SHA1 + 64 bytes output).
func HashPassword(password string) (out PasswordHash) {
    // random salt
    salt := make([]byte, 16)
    _, err := io.ReadFull(rand.Reader, salt)
    if err != nil {
        panic("pbkdf2.HashPassword: Random-number source malfunction!")
    }

    return HashPasswordWith(salt, password)
}

// Call Pbkdf2 with reasonable defaults (9999 iterations + SHA1 + 64 bytes output).
func HashPasswordWith(salt []byte, password string) (out PasswordHash) {
    return PasswordHash{salt, Pbkdf2([]byte(password), salt, 9999, sha1.New, 64)}
}

func MatchPassword(password string, phash PasswordHash) bool {
    hash := Pbkdf2([]byte(password), phash.Salt, 9999, sha1.New, 64)
    return subtle.ConstantTimeCompare(hash, phash.Hash) == 1
}


