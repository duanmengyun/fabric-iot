package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"gitee.com/frankyu365/gocrypto/util"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

// 生成公私钥
func GenKeyPair() (privateKey string, publicKey string, e error) {
	// GenerateKey生成公私钥对。
	// priKey --- priv.PublicKey.X, priv.PublicKey.Y
	priKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", "", e
	}
	// 将一个EC私钥转换为SEC 1, ASN.1 DER格式。
	ecPrivateKey, e := x509.MarshalECPrivateKey(priKey)
	if e != nil {
		return "", "", e
	}
	// 私钥
	privateKey = base64.StdEncoding.EncodeToString(ecPrivateKey)

	X := priKey.X
	Y := priKey.Y
	xStr, e := X.MarshalText()
	if e != nil {
		return "", "", e
	}
	yStr, e := Y.MarshalText()
	if e != nil {
		return "", "", e
	}
	public := string(xStr) + "+" + string(yStr)
	// 公钥 x+y
	publicKey = base64.StdEncoding.EncodeToString([]byte(public))
	return
}

// 解析私钥
func BuildPrivateKey(privateKeyStr string) (priKey *ecdsa.PrivateKey, e error) {
	bytes, e := base64.StdEncoding.DecodeString(privateKeyStr)
	if e != nil {
		return nil, e
	}
	// ParseECPrivateKey解析SEC 1, ASN.1 DER形式的EC私钥。
	priKey, e = x509.ParseECPrivateKey(bytes)
	if e != nil {
		return nil, e
	}
	return
}

// 解析公钥
func BuildPublicKey(publicKeyStr string) (pubKey *ecdsa.PublicKey, e error) {
	bytes, e := base64.StdEncoding.DecodeString(publicKeyStr)
	if e != nil {
		return nil, e
	}
	split := strings.Split(string(bytes), "+")
	xStr := split[0]
	yStr := split[1]
	x := new(big.Int)
	y := new(big.Int)
	e = x.UnmarshalText([]byte(xStr))
	if e != nil {
		return nil, e
	}
	e = y.UnmarshalText([]byte(yStr))
	if e != nil {
		return nil, e
	}
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	pubKey = &pub
	return
}

// 签名
func Sign(content string, privateKeyStr string) (signature string, e error) {
	priKey, e := BuildPrivateKey(privateKeyStr)
	if e != nil {
		return "", e
	}
	// 随机数，用户私钥，hash签署消息
	r, s, e := ecdsa.Sign(rand.Reader, priKey, []byte(hash(content)))
	if e != nil {
		return "", e
	}
	rt, e := r.MarshalText()
	st, e := s.MarshalText()
	// r+s
	signStr := string(rt) + "+" + string(st)
	signature = hex.EncodeToString([]byte(signStr))
	return
}

// 验签  内容 签名，公钥
func VerifySign(content string, signature string, publicKeyStr string) bool {
	decodeSign, e := hex.DecodeString(signature)
	if e != nil {
		return false
	}
	// +号 签名 切片
	split := strings.Split(string(decodeSign), "+")
	rStr := split[0]
	sStr := split[1]
	rr := new(big.Int)
	ss := new(big.Int)
	e = rr.UnmarshalText([]byte(rStr))
	e = ss.UnmarshalText([]byte(sStr))
	pubKey, e := BuildPublicKey(publicKeyStr)
	if e != nil {
		return false
	}
	// 验签，公钥 hash签署消息 签名值（r，s）
	return ecdsa.Verify(pubKey, []byte(hash(content)), rr, ss)
}

// Hash算法，这里是sha256，可以根据需要自定义
func hash(data string) string {
	sum := sha256.Sum256([]byte(data))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func main() {
	fmt.Println("选择生成主设备密钥对或者生成信任凭证: ")
	fmt.Println("输入1：生成ECC密钥对      输入2：生成信任凭证      输入3：用户注册       输入4：加密数据      输入5：退出")
	var number int
	number = 0
	for number != 5 {
		fmt.Scanln(&number)
		fmt.Print(number)
		//给主设备分配公私钥，然后自己存储到设备上
		if number == 1 {
			privateKey, publicKey, err := GenKeyPair()
			if err != nil {
				panic(err)
			}
			fmt.Printf("privateKey:%s\n publicKey:%s\n", privateKey, publicKey)
		}
		if number == 2 {
			//从设备分配信任凭证
			//主设备公私钥
			var prikey_master string
			fmt.Printf("请输入主设备私钥\n")
			fmt.Scanln(&prikey_master)
			var domainid []byte
			var deviceid []byte
			fmt.Printf("请输入从设备id\n")
			fmt.Scanln(&deviceid)
			fmt.Printf("请输入域id\n")
			fmt.Scanln(&domainid)
			info := string(deviceid) + string(domainid)
			ticket, err := Sign(info, prikey_master)
			if err != nil {
				panic(err)
			}
			fmt.Printf("ticket：")
			fmt.Printf(ticket + "\n")
		}
		if number == 3 {
			var userid string
			fmt.Printf("请输入用户id")
			fmt.Scanln(&userid)
			var role string
			var group string
			fmt.Printf("请输入用户的身份\n")
			fmt.Scanln(&role)
			fmt.Printf("请输入用户所在的组织\n")
			fmt.Scanln(&group)
			var prikey_master string
			fmt.Printf("请输入主设备私钥\n")
			fmt.Scanln(&prikey_master)
			info := string(userid) + string(role) + string(group)
			ticket, err := Sign(info, prikey_master)
			if err != nil {
				panic(err)
			}
			fmt.Printf("ticket：")
			fmt.Printf(ticket + "\n")
		}
		if number == 5 {
			fmt.Printf("退出")
		}
		if number == 4 {
			var url string
			fmt.Printf("输入加密数据")
			fmt.Scanln(&url)
			var pubKey string
			fmt.Printf("输入加密公钥")
			fmt.Scanln(&pubKey)
			publicKey, _ := BuildPublicKey(pubKey)
			cipherText, _ := ecies.Encrypt(rand.Reader, util.PubEcdsaToEcies(publicKey), []byte(url), nil, nil)
			encodeString := base64.StdEncoding.EncodeToString(cipherText)
			fmt.Println(encodeString)
			decodeBytes, _ := base64.StdEncoding.DecodeString(encodeString)
			fmt.Print(decodeBytes)
			fmt.Print(cipherText)
		}
	}
}
