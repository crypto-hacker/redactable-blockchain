package chameleon
//package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
	"golang.org/x/crypto/sha3"
	"hash"
	"math/big"
)

var (
	Tao   = big.NewInt(256) // Parameter of chameleon hash.
	Kappa = big.NewInt(256) // Parameter of chameleon hash.

	customizedIdentity = []byte("Hello world!")
	j                  = new(big.Int)
	p                  = new(big.Int)
	q                  = new(big.Int)
	n                  = new(big.Int)
	e                  = new(big.Int)
	d                  = new(big.Int)
	//keys = generateKey()
	//p    = keys[0]
	//q    = keys[1]
	//n    = keys[2]
	//e    = keys[3]
	//d    = keys[4]
)

func init() {
	h := sha3.NewLegacyKeccak256()
	h.Write(customizedIdentity)
	jHash := h.Sum(nil)
	h.Reset()
	//jBytes, err := emsaPSSEncode(jHash, 256, []byte{1}, h)
	jBytes, err := emsaPSSEncode(jHash, 360, []byte{1}, h)
	if err != nil {
		log.Warn("Emsa pass encode err %s", err)
		return
	}
	j.SetBytes(jBytes)

	p.SetString("d0c1baff1b227fb6dc35150c217467aeede5e30babbdff7407bba941b64a4669", 16)
	q.SetString("ce66f004358b85619abae98c5ad95bf21e0b0a5aa5f0c37f65aca1e58314fc67", 16)
	n.SetString("a84fd562d77a899c63311b03dd83ec4636096bfbf5edc97b29b1c67d03575e1aa28bebeb0e4f66fd99809b83bcf3bafe61e7d837bd3b0dc432cd0da3b065b03f", 16)
	e.SetString("01e34970639f9a14dbe7386be418345c7743ab116200e78b11502f84a8d83e6a2f", 16)
	d.SetString("9dd1141a3f48a5f2d210af79427229a5fb1a59b6b2fb2b5a7ef91da9682af0e2b6fb2beebce4b3f2625a098703793828c99bc0bb0f8a50ff77ae96c242ec4b8f", 16)
}

// From Go/src/crypto/rsa/pss.go.
func emsaPSSEncode(mHash []byte, emBits int, salt []byte, hash hash.Hash) ([]byte, error) {
	// See [1], section 9.1.1
	hLen := hash.Size()
	sLen := len(salt)
	emLen := (emBits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

	if len(mHash) != hLen {
		return nil, errors.New("crypto/rsa: input must be hashed message")
	}

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

	if emLen < hLen+sLen+2 {
		return nil, errors.New("crypto/rsa: key size too small for PSS signature")
	}

	em := make([]byte, emLen)
	db := em[:emLen-sLen-hLen-2+1+sLen]
	h := em[emLen-sLen-hLen-2+1+sLen : emLen-1]

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

	var prefix [8]byte

	hash.Write(prefix[:])
	hash.Write(mHash)
	hash.Write(salt)

	h = hash.Sum(h[:0])
	hash.Reset()

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

	db[emLen-sLen-hLen-2] = 0x01
	copy(db[emLen-sLen-hLen-1:], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

	mgf1XOR(db, hash, h)

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

	db[0] &= 0xFF >> uint(8*emLen-emBits)

	// 12. Let EM = maskedDB || H || 0xbc.
	em[emLen-1] = 0xBC

	// 13. Output EM.
	return em, nil
}

// From Go/src/crypto/rsa/pss.go.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// From Go/src/crypto/rsa/pss.go.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}

func generateKey() []*big.Int {
	one := big.NewInt(1)
	two := big.NewInt(2)

	var p *big.Int
	pLimit := new(big.Int).Set(two)
	pLimit.Exp(pLimit, Kappa.Sub(Kappa, one), nil)
	for {
		p, _ = rand.Prime(rand.Reader, int(Kappa.Int64())+1)
		if p.Cmp(pLimit) == 1 {
			break
		}
	}

	var q *big.Int
	qLimit := new(big.Int).Set(two)
	qLimit.Exp(qLimit, Kappa.Add(Kappa, one), nil)
	qLimit.Sub(qLimit, one)
	for {
		q, _ = rand.Prime(rand.Reader, int(Kappa.Int64()))
		if q.Cmp(qLimit) == -1 {
			break
		}
	}

	n := new(big.Int)
	n.Mul(p, q)

	euler := new(big.Int)
	qSub := new(big.Int)
	qSub.SetBytes(q.Bytes())
	qSub.Sub(qSub, one)
	pSub := new(big.Int)
	pSub.SetBytes(p.Bytes())
	pSub.Sub(pSub, one)
	euler.Mul(pSub, qSub)

	var e *big.Int
	eLimit := new(big.Int).Set(two)
	eLimit.Exp(eLimit, Tao, nil)
	gcd := new(big.Int)
	for {
		e, _ = rand.Prime(rand.Reader, int(Tao.Int64())+1)
		gcd = gcd.GCD(nil, nil, e, euler)
		if e.Cmp(eLimit) == 1 && gcd.Cmp(one) == 0 {
			break
		}
	}

	d := new(big.Int)
	d.ModInverse(e, euler)

	fmt.Println(hex.EncodeToString(p.Bytes()), "p")
	fmt.Println(hex.EncodeToString(q.Bytes()), "q")
	fmt.Println(hex.EncodeToString(n.Bytes()), "n")
	fmt.Println(hex.EncodeToString(e.Bytes()), "e")
	fmt.Println(hex.EncodeToString(d.Bytes()), "d")
	return []*big.Int{p, q, n, e, d}
}

func Hash(msg common.Hash, salt []byte) common.Hash {
	reverseMsg := new(big.Int).SetBytes(msg.Bytes())
	reverseSalt := new(big.Int).SetBytes(salt)

	jHm := new(big.Int)
	jHm.Exp(j, reverseMsg, n)
	rE := new(big.Int)
	rE.Exp(reverseSalt, e, n)
	re := new(big.Int)
	re.Mul(jHm, rE)
	re.Mod(re, n)

	return common.BytesToHash(re.Bytes())
}

func UForge(oldMsg, newMsg common.Hash, oldSalt []byte) *big.Int {
	reverseOldMsg := new(big.Int).SetBytes(oldMsg.Bytes())
	reverseNewMsg := new(big.Int).SetBytes(newMsg.Bytes())
	reverseOldSalt := new(big.Int).SetBytes(oldSalt)

	b := new(big.Int)
	b.Exp(j, d, n)
	hM := new(big.Int).Sub(reverseOldMsg, reverseNewMsg)
	bHmMod := new(big.Int).Exp(b, hM, n)
	rMod := new(big.Int).Mod(reverseOldSalt, n)
	re := new(big.Int)
	re.Mul(bHmMod, rMod)
	re.Mod(re, n)

	return re
}
