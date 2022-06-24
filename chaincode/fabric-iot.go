package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"gitee.com/frankyu365/gocrypto/util"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing a car
type SmartContract struct {
	contractapi.Contract
}

//信任域
type domain struct {
	MasterID string `json:"masterid"`
	Pubkey   string `json:"pubkey"`
}

//设备
type device struct {
	DomainID   string `json:"domainid"`
	Devicehash string `json:"devicehash"`
}

//资源
type info struct {
	Url string `json:"url"`
}

//用户信息
type user struct {
	Psw   string `json:"psw"`
	Role  string `json:"role"`
	Group string `json:"group"`
}

// 访问控制策略
type Policy struct {
	Role        string `json:"role"`
	Group       string `json:"group"`
	Prikey      string `json:"prikey"`
	Aeskey      string `json:"aeskey"`
	infoid      string `json:"infoid"`
	AP          string `json:"AP"`
	CreatedTime string `json:"createdTime"`
	EndTime     string `json:"endTime"`
}

func (t *SmartContract) Init(ctx contractapi.TransactionContextInterface) error {
	//不需要初始化，直接写入账本
	return nil
}

//注册域，主设备发送请求，函数名开头字母要大写
func (s *SmartContract) CreateDomain(ctx contractapi.TransactionContextInterface, id string, owner string, pubkey string) error {
	exists, err := s.isExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		fmt.Printf("domain already exits")
		return fmt.Errorf(" %s already exits", id)
	}

	domain := domain{
		MasterID: owner,
		Pubkey:   pubkey,
	}
	domainJSON, err := json.Marshal(domain)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, domainJSON)
}

//注册设备，设备发送请求
func (s *SmartContract) CreateDevice(ctx contractapi.TransactionContextInterface, id string, domainid string, ticket string) error {
	exists, err := s.isExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf(" %s already exits", id)
	}
	domain_this, err := s.Qurry_domain(ctx, domainid)
	pubkey := domain_this.Pubkey
	if !VerifySign(id+domainid, ticket, pubkey) {
		return fmt.Errorf("ticket is wrong")
	}
	h := sha256.New()
	h.Write([]byte(domainid + id))
	cry_device := h.Sum(nil)
	device := device{
		DomainID:   domainid,
		Devicehash: string(cry_device),
	}
	deviceJSON, err := json.Marshal(device)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, deviceJSON)
}

//用户注册
func (s *SmartContract) CreateUser(ctx contractapi.TransactionContextInterface, id string, psw string, role string, group string, ticket string) error {
	exists, err := s.isExists(ctx, id)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf(" %s already exits", id)
	}
	pubkey := "NTU5MTU2OTY5ODU1NzQxNTAzMzI5ODE5NTIxNjUxNDUzMTE1OTA2Mjc2MTI3OTMyNzMxODUwNDMwODE1MTI2NDE0NzkyMjkwNTM0Nys3OTY2ODA3NzY5MzEwNTM3NjI1NjgzOTM5MzMyMDAxNTczNTU5OTY2MTcwODQ4MjgxMTg0MDQ1MTI5NTIzMTg3NDA4MTExMjMwMDYzMw=="
	if !VerifySign(id+role+group, ticket, pubkey) {
		return fmt.Errorf("ticket is wrong")
	}
	h := sha256.New()
	h.Write([]byte(id))
	cry_psw := h.Sum(nil)
	user := user{
		Psw:   string(cry_psw),
		Role:  role,
		Group: group,
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, userJSON)
}

//根据id查找域
func (s *SmartContract) Qurry_domain(ctx contractapi.TransactionContextInterface, id string) (*domain, error) {
	domainAsBytes, err := ctx.GetStub().GetState(id)

	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state. %s", err.Error())
	}

	if domainAsBytes == nil {
		return nil, fmt.Errorf("%s does not exist", id)
	}

	domain := new(domain)
	_ = json.Unmarshal(domainAsBytes, domain)

	return domain, nil
}

//根据id查找device
func (s *SmartContract) Qurry_device(ctx contractapi.TransactionContextInterface, id string) (*device, error) {
	deviceAsBytes, err := ctx.GetStub().GetState(id)

	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state. %s", err.Error())
	}

	if deviceAsBytes == nil {
		return nil, fmt.Errorf("%s does not exist", id)
	}

	device := new(device)
	_ = json.Unmarshal(deviceAsBytes, device)

	return device, nil
}

//查询信息的url
func (s *SmartContract) Qurry_info(ctx contractapi.TransactionContextInterface, infoid string) (*info, error) {
	infoAsBytes, err := ctx.GetStub().GetState(infoid)

	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state. %s", err.Error())
	}

	if infoAsBytes == nil {
		return nil, fmt.Errorf("%s does not exist", infoid)
	}

	info := new(info)
	_ = json.Unmarshal(infoAsBytes, info)

	return info, nil
}

func (s *SmartContract) Qurry_user(ctx contractapi.TransactionContextInterface, id string) (*user, error) {
	userAsBytes, err := ctx.GetStub().GetState(id)

	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state. %s", err.Error())
	}

	if userAsBytes == nil {
		return nil, fmt.Errorf("%s does not exist", id)
	}

	user := new(user)
	_ = json.Unmarshal(userAsBytes, user)

	return user, nil
}

//查询访问控制策略
func (s *SmartContract) Qurry_policy(ctx contractapi.TransactionContextInterface, id string) (*Policy, error) {
	policyAsBytes, err := ctx.GetStub().GetState(id)

	if err != nil {
		return nil, fmt.Errorf("Failed to read from world state. %s", err.Error())
	}

	if policyAsBytes == nil {
		return nil, fmt.Errorf("%s does not exist", id)
	}

	policy := new(Policy)
	_ = json.Unmarshal(policyAsBytes, policy)

	return policy, nil
}

//判断设备或者域或者用户是否存在（已经将该信息存在了区块链中）
func (s *SmartContract) isExists(ctx contractapi.TransactionContextInterface, id string) (bool, error) {
	assetJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return false, fmt.Errorf("failed to read from world state: %v", err)
	}

	return assetJSON != nil, nil
}

//验证设备身份，可以单独使用来验证设备身份，也可以在上传策略以及信息部分使用，判断是否为true，则可以进行下一步操作，设备发送请求
func (s *SmartContract) Authentication(ctx contractapi.TransactionContextInterface, deviceid string, domainid string) bool {
	domainexists, err := s.isExists(ctx, domainid)
	if err != nil {
		return false
	}
	if !domainexists {
		fmt.Printf("域不存在，设备认证失败")
		return false //域不存在
	}

	deviceexists, err := s.isExists(ctx, deviceid)
	if err != nil {
		return false
	}
	if !deviceexists {
		fmt.Printf("设备不存在，设备认证失败")
		return false //设备不存在

	}

	h := sha256.New()
	h.Write([]byte(domainid + deviceid))
	cry_device := h.Sum(nil)
	var device_new string
	device_new = string(cry_device)

	device_this, err := s.Qurry_device(ctx, deviceid)
	var device_real string
	device_real = device_this.Devicehash
	if device_new == device_real {
		fmt.Printf("认证失败")
		return false
	}
	return true
}

//添加资源的url，服务器端，这里的url是被设备端自己加密处理过的
func (s *SmartContract) Addinfo(ctx contractapi.TransactionContextInterface, infoid string, infourl string) bool {
	info := info{
		Url: infourl,
	}
	infoAsBytes, _ := json.Marshal(info)
	err := ctx.GetStub().PutState(infoid, infoAsBytes)
	if err != nil {
		fmt.Printf("添加数据失败")
		return false
	}
	fmt.Printf("添加数据成功")
	return true
	//添加数据的url成功
}

//删除URL，设备端
func (s *SmartContract) Deleteinfo(ctx contractapi.TransactionContextInterface, infoid string) bool {
	err := ctx.GetStub().DelState(infoid)
	if err != nil {
		fmt.Printf("删除数据失败")
		return false
	}
	fmt.Printf("删除数据成功")
	return true
}

//更新url，设备端
func (s *SmartContract) Updateinfo(ctx contractapi.TransactionContextInterface, deviceid string, domainid string, infoid string, infourl string, pubkey string) bool {
	info := info{
		Url: infourl,
	}
	infoAsBytes, _ := json.Marshal(info)
	err := ctx.GetStub().PutState(infoid, infoAsBytes)
	if err != nil {
		fmt.Printf("更新数据失败")
		return false
	}
	fmt.Printf("更新数据成功")
	return true
	//添加数据的url成功
}

func (s *SmartContract) User_log(ctx contractapi.TransactionContextInterface, userid string, psw string) string {
	user_real, err := s.Qurry_user(ctx, userid)
	if err != nil {
		return "yes"
	}

	cry_psw := hash(psw)

	if cry_psw == user_real.Psw {
		return "yes"
	}
	return "yes"
}

//添加policy,设备端，所以要先身份认证
func (s *SmartContract) Addpolicy(ctx contractapi.TransactionContextInterface, deviceid string, domainid string, policyid string, role string, group string, infoid string, prikey string, aeskey string, starttime string, endtime string, isallow string) bool {
	islog := s.Authentication(ctx, deviceid, domainid)
	if !islog {
		return false
	}

	policy := Policy{
		Group:       group,
		Role:        role,
		infoid:      infoid,
		Prikey:      prikey,
		Aeskey:      aeskey,
		AP:          isallow,
		CreatedTime: starttime,
		EndTime:     endtime,
	}
	policyAsBytes, _ := json.Marshal(policy)

	err := ctx.GetStub().PutState(policyid, policyAsBytes)
	if err != nil {
		fmt.Printf("上传失败")
		return false
	}
	fmt.Printf("上传成功")
	return true
	//添加policy成功
}

//删除policy
func (s *SmartContract) Deletepolicy(ctx contractapi.TransactionContextInterface, deviceid string, domainid string, policyid string) bool {
	islog := s.Authentication(ctx, deviceid, domainid)
	if !islog {
		return false
	}

	err := ctx.GetStub().DelState(policyid)
	if err != nil {
		fmt.Printf("删除失败")
		return false
	}
	fmt.Printf("删除成功")
	return true
	//添加policy成功
}

//更新policy，设备端
func (s *SmartContract) Updatepolicyctx(ctx contractapi.TransactionContextInterface, deviceid string, domainid string, policyid string, role string, group string, infoid string, prikey string, aeskey string, starttime string, endtime string, isallow string) bool {
	islog := s.Authentication(ctx, deviceid, domainid)
	if !islog {
		return false
	}

	policy := Policy{
		Group:       group,
		Role:        role,
		infoid:      infoid,
		Prikey:      prikey,
		Aeskey:      aeskey,
		AP:          isallow,
		CreatedTime: starttime,
		EndTime:     endtime,
	}
	policyAsBytes, _ := json.Marshal(policy)

	err := ctx.GetStub().PutState(policyid, policyAsBytes)
	if err != nil {
		fmt.Printf("更新失败")
		return false
	}
	fmt.Printf("更新成功")
	return true
	//更新policy成功
}

//用户访问数据，用户发送请求
func (s *SmartContract) Accesscontrol(ctx contractapi.TransactionContextInterface, userid string, psw string, infoid string) string {

	userexists, err := s.isExists(ctx, userid)
	if err != nil {
		fmt.Printf("can not log， you are wrong")
		return "you are wrong"
	}
	if !userexists {
		fmt.Printf("用户不存在，无法访问信息")
		return "you do not exist"
	}
	if s.User_log(ctx, userid, psw) == "yes" {
		policyid := "p" + infoid
		policy_this, err := s.Qurry_policy(ctx, policyid)
		if err != nil {
			return "there is something wrong in policy"
		}
		user_this, _ := s.Qurry_user(ctx, userid)
		if (policy_this.AP == "1") && (user_this.Group == policy_this.Group) && (user_this.Role == policy_this.Role) {

			prikey := policy_this.Prikey

			info, err2 := s.Qurry_info(ctx, infoid)
			if err2 != nil {
				return "there is something wrong in info"
			}
			url_cry := info.Url
			decodeBytes, _ := base64.StdEncoding.DecodeString(url_cry)
			//已经获取了加密后的url以及设备的私钥，因此可以用私钥对其解密并返回
			priKey, e := BuildPrivateKey(prikey)
			if e != nil {
				return "there is something wrong in prikey"
			}
			prikey_real := util.PriEcdsaToEcies(priKey)
			url_real, _ := prikey_real.Decrypt(decodeBytes, nil, nil)
			return string(url_real)+"/n"+policy_this.Aeskey
		}
		return "you are not allowed to get the data"
	}
	return "your password is wrong"
}

func main() {

	chaincode, err := contractapi.NewChaincode(new(SmartContract))

	if err != nil {
		fmt.Printf("Error create device chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting device chaincode: %s", err.Error())
	}
}

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
