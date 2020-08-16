package chameleon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"golang.org/x/crypto/scrypt"
	"io"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"
)

func Test(t *testing.T) {
	test := "Hello world!"
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(test))
	testHash := common.BytesToHash(h.Sum(nil))
	testSalt := []byte{1, 2, 3}
	fmt.Println(Hash(testHash, testSalt).String())

	h.Reset()

	test1 := "It's a beautiful day!"
	h.Write([]byte(test1))
	test1Hash := common.BytesToHash(h.Sum(nil))
	test1Salt := UForge(testHash, test1Hash, testSalt).Bytes()

	fmt.Println(Hash(test1Hash, test1Salt).String())
}

func TestAccount(t *testing.T) {
	var privateKey *ecdsa.PrivateKey
	{
		// 模拟以太坊账户生成。geth代码位置：/accounts/keystore/key.go/newKey()。

		ec := crypto.S256()

		// 生成椭圆曲线密码的公钥和私钥。
		privateKey, _ = ecdsa.GenerateKey(ec, rand.Reader)
		fmt.Println("private key: ", "0x"+ hex.EncodeToString(privateKey.D.Bytes()))
		fmt.Println("x of public key: ", "0x"+hex.EncodeToString(privateKey.PublicKey.X.Bytes()))
		fmt.Println("y of public key: ", "0x"+hex.EncodeToString(privateKey.PublicKey.Y.Bytes()))

		// 将公钥转化为账户地址: 首先将公钥中的X点和Y点根据section 4.3.6 of ANSI X9.62转换为
		// byte切片，将该byte切片的有效部分（从第二位起）进行keccak256运算，得到的结果取其后20
		// 位即得到地址。。
		bytePub := elliptic.Marshal(ec, privateKey.PublicKey.X, privateKey.PublicKey.Y)
		address := common.BytesToAddress(crypto.Keccak256(bytePub[1:])[12:])
		fmt.Println("address: ", address.String())
	}

	var (
		keyBytesOfPrivateKey []byte

		salt                []byte
		privateKeyOfEncrypt []byte
		mac                 []byte
		iv                  []byte
		derivedKey          []byte
	)
	const (
		// scrypt算法的常量参数。
		standardScryptN = 1 << 18
		standardScryptP = 1
		scryptR         = 8

		// scrypt算法生成key的长度。
		scryptDKLen = 32
	)
	{
		// 模拟以太坊使用AES加密私钥的过程。
		// geth代码位置：/accounts/keystore/passphrase.go/EncryptKey()。

		passwordOfCreateAccount := []byte("hello world")

		// 将私钥转换为至少32位的byte切片，如果小于32位，则使用0补齐。
		keyBytesOfPrivateKey = math.PaddedBigBytes(privateKey.D, 32)
		// 生成scrypt算法所需的32位随机byte切片。
		salt = make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, salt)
		// 使用scrypt算法生成的AES加密密钥，前16位用于生成mac以验证
		// 用户输入密码的有效性，后16位用于加密椭圆曲线私钥。
		derivedKey, _ = scrypt.Key(
			passwordOfCreateAccount,
			salt,
			standardScryptN,
			scryptR,
			standardScryptP,
			scryptDKLen,
		)
		// AES加密密钥。
		encryptKey := derivedKey[:16]
		// 规定AES分组大小。
		iv = make([]byte, aes.BlockSize)
		_, _ = io.ReadFull(rand.Reader, iv)
		// 采用CTR模式对椭圆曲线私钥进行加密。
		aesBlock, _ := aes.NewCipher(encryptKey)
		stream := cipher.NewCTR(aesBlock, iv)
		privateKeyOfEncrypt = make([]byte, len(keyBytesOfPrivateKey))
		stream.XORKeyStream(privateKeyOfEncrypt, keyBytesOfPrivateKey)
		// 生成mac。
		mac = crypto.Keccak256(derivedKey[16:32], privateKeyOfEncrypt)

		fmt.Println("salt: ", "0x"+hex.EncodeToString(salt))
		fmt.Println("encrypted private key: ", "0x"+hex.EncodeToString(privateKeyOfEncrypt))
		fmt.Println("mac: ", "0x"+hex.EncodeToString(mac))
		fmt.Println("iv: ", "0x"+hex.EncodeToString(iv))
		fmt.Println("derivedKey: ", "0x"+hex.EncodeToString(derivedKey))
	}

	{
		// 模拟以太坊使用AES解密私钥的过程。
		// geth代码位置：/accounts/keystore/passphrase.go/DecryptKey()。

		passwordOfUnlockAccount := []byte("hello world")

		// 验证用户输入密码是否有效。
		derivedKey, _ := scrypt.Key(
			passwordOfUnlockAccount,
			salt,
			standardScryptN,
			scryptR,
			standardScryptP,
			scryptDKLen,
		)
		calculatedMAC := crypto.Keccak256(derivedKey[16:32], privateKeyOfEncrypt)
		if !bytes.Equal(calculatedMAC, mac) {
			panic("输入密码错误")
		}
		// 采用CTR模式对椭圆曲线私钥进行解密。
		aesBlock, _ := aes.NewCipher(derivedKey[:16])
		stream := cipher.NewCTR(aesBlock, iv)
		privateKeyOfDecrypt := make([]byte, len(privateKeyOfEncrypt))
		stream.XORKeyStream(privateKeyOfDecrypt, privateKeyOfEncrypt)

		fmt.Println("decrypted private key: ", "0x"+hex.EncodeToString(privateKeyOfDecrypt))
		fmt.Println("is equal to key bytes of private key: ", bytes.Equal(keyBytesOfPrivateKey, privateKeyOfDecrypt))
	}
}
