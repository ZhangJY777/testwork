package main

import (
	"fmt"
	"os"
	"testwork/sdkInit"
)
const (
	cc_name = "test"
	cc_version = "1.0"
)

var App sdkInit.Application //app

//数据上传到ipfs
//1.初始化Hyperledger Fabric SDK。
//2.创建并加入通道。
//3.安装和初始化链码。
//4.设置链码状态。
func main()  {
	//org信息
	orgs := []*sdkInit.OrgInfo{
		{
			OrgAdminUser:  "Admin",
			OrgName:       "Org1",
			OrgMspId:      "Org1MSP",
			OrgUser:       "User1",
			OrgPeerNum:    2,
			OrgAnchorFile: "/root/testwork/fixtures/channel-artifacts/Org1MSPanchors.tx",
		},
		{
			OrgAdminUser:  "Admin",
			OrgName:       "Org2",
			OrgMspId:      "Org2MSP",
			OrgUser:       "User1",
			OrgPeerNum:    2,
			OrgAnchorFile: "/root/testwork/fixtures/channel-artifacts/Org2MSPanchors.tx",
		},
	}
	// 初始化info
	info := sdkInit.SdkEnvInfo{
		ChannelID:        "mychannel",
		ChannelConfig:    "/root/testwork/fixtures/channel-artifacts/channel.tx",
		Orgs:             orgs,
		OrdererAdminUser: "Admin",
		OrdererOrgName:   "OrdererOrg",
		OrdererEndpoint:  "orderer1.example.com",
		ChaincodeID:      cc_name,
		ChaincodePath:    "/root/testwork/chaincode/go/test",
		ChaincodeVersion: cc_version,
	}
	sdk, err := sdkInit.Setup("config.yaml", &info)
	if err != nil{
		fmt.Println(">> Sdk set error ", err)
		os.Exit(-1)
	}
		if err := sdkInit.CreateChannel(&info); err != nil{
			fmt.Println(">> Create channel error: ", err)
			os.Exit(-1)
		}
		if err := sdkInit.JoinChannel(&info); err != nil{
			fmt.Println(">> join channel error: ", err)
			os.Exit(-1)
		}
		//chaincode operation安装链码
		packageID, err := sdkInit.InstallCC(&info)
		if err != nil{
			fmt.Println(">> install chaincode error: ", err)
			os.Exit(-1)
		}
		//apprrove链码更新组织批准
		if err := sdkInit.ApproveLifecycle(&info, 1, packageID); err != nil{
			fmt.Println(">> approve chaincode error: ", err)
			os.Exit(-1)
		}
		//init chaincode
		if err := sdkInit.InitCC(&info, false, sdk); err != nil{
			fmt.Println(">> init chaincode error: ", err)
			os.Exit(-1)
		}
	fmt.Println(">> Set the chain code status through the chain code external service......")
	if err := info.InitService(info.ChaincodeID, info.ChannelID, info.Orgs[0], sdk);err != nil{
		fmt.Println(">> InitService error: ", err)
		os.Exit(-1)
	}
	App=sdkInit.Application{
		SdkEnvInfo: &info,
	}
	fmt.Println(">> Set chain code status completed")

}

//package main
//
//import (
//	"crypto/ecdsa"
//	"crypto/elliptic"
//	"crypto/rand"
//	"crypto/sha256"
//	"encoding/json"
//	"fmt"
//	"math/big"
//)
//
//// 环签名结构
//type RingSignature struct {
//	PublicKeys []*ecdsa.PublicKey // 环中的公钥集合
//	C          *big.Int           // 挑战值
//	S          []*big.Int         // 签名值集合
//}
//
//// 生成环签名
//func SignRing(message []byte, privKey *ecdsa.PrivateKey, publicKeys []*ecdsa.PublicKey) (*RingSignature, error) {
//	n := len(publicKeys)
//	if n == 0 {
//		return nil, fmt.Errorf("至少需要一个公钥")
//	}
//
//	// 1. 计算消息哈希
//	hash := sha256.Sum256(message)
//
//	// 2. 找到签名者在环中的位置
//	k := -1
//	for i, pk := range publicKeys {
//		if pk.X.Cmp(privKey.X) == 0 && pk.Y.Cmp(privKey.Y) == 0 {
//			k = i
//			break
//		}
//	}
//	if k == -1 {
//		return nil, fmt.Errorf("私钥未在公钥列表中")
//	}
//
//	curve := elliptic.P256()
//	params := curve.Params()
//	//nMinus1 := big.NewInt(int64(n - 1))
//
//	// 3. 初始化参数
//	s := make([]*big.Int, n)
//	c := make([]*big.Int, n)
//
//	// 4. 生成随机数v (实际应为k+1的挑战)
//	v, _ := rand.Int(rand.Reader, params.N)
//	c[(k+1)%n] = new(big.Int).SetBytes(hash[:])
//	c[(k+1)%n].Mod(c[(k+1)%n], params.N)
//
//	// 5. 前向计算环
//	i := (k + 1) % n
//	for i != k {
//		// 生成随机s[i]
//		s[i], _ = rand.Int(rand.Reader, params.N)
//
//		// 计算下一挑战
//		sGx, sGy := curve.ScalarBaseMult(s[i].Bytes())
//		cPx, cPy := curve.ScalarMult(publicKeys[i].X, publicKeys[i].Y, c[i].Bytes())
//		sumX, sumY := curve.Add(sGx, sGy, cPx, cPy)
//
//		hashInput := append(sumX.Bytes(), sumY.Bytes()...)
//		hashInput = append(hashInput, message...)
//		nextHash := sha256.Sum256(hashInput)
//
//		next := (i + 1) % n
//		c[next] = new(big.Int).SetBytes(nextHash[:])
//		c[next].Mod(c[next], params.N)
//
//		i = (i + 1) % n
//	}
//
//	// 6. 关闭环
//	s[k] = new(big.Int).Sub(v, new(big.Int).Mul(c[k], privKey.D))
//	s[k].Mod(s[k], params.N)
//
//	return &RingSignature{
//		PublicKeys: publicKeys,
//		C:          c[0],
//		S:          s,
//	}, nil
//}
//
//// 验证环签名
//func VerifyRing(message []byte, sig *RingSignature) bool {
//	n := len(sig.PublicKeys)
//	if n == 0 {
//		return false
//	}
//
//	curve := elliptic.P256()
//	params := curve.Params()
//	c := make([]*big.Int, n)
//	c[0] = new(big.Int).Set(sig.C)
//
//	// 重构挑战链
//	for i := 0; i < n; i++ {
//		// 计算sG + cP
//		sGx, sGy := curve.ScalarBaseMult(sig.S[i].Bytes())
//		cPx, cPy := curve.ScalarMult(sig.PublicKeys[i].X, sig.PublicKeys[i].Y, c[i].Bytes())
//		sumX, sumY := curve.Add(sGx, sGy, cPx, cPy)
//
//		// 计算下一挑战
//		hashInput := append(sumX.Bytes(), sumY.Bytes()...)
//		hashInput = append(hashInput, message...)
//		nextHash := sha256.Sum256(hashInput)
//
//		next := (i + 1) % n
//		if next == 0 {
//			break
//		}
//		c[next] = new(big.Int).SetBytes(nextHash[:])
//		c[next].Mod(c[next], params.N)
//	}
//
//	// 验证环闭合
//	return c[0].Cmp(sig.C) == 0
//}
//
//func main() {
//	// 生成测试密钥环
//	curve := elliptic.P256()
//
//	// 生成三个密钥对
//	priv1, _ := ecdsa.GenerateKey(curve, rand.Reader)
//
//	putData, err := json.Marshal(priv1)
//	if err != nil {
//		fmt.Errorf("Failed to json2 asset: %s", err)
//	}
//	priv := &ecdsa.PrivateKey{}
//	err = json.Unmarshal(putData, &priv)
//	if err != nil {
//		fmt.Errorf("Failed to json asset: %s", err)
//	}
//
//	priv2, _ := ecdsa.GenerateKey(curve, rand.Reader)
//	priv3, _ := ecdsa.GenerateKey(curve, rand.Reader)
//
//	publicKeyss := []*ecdsa.PublicKey{}
//
//	publicKeys := []*ecdsa.PublicKey{
//		&priv1.PublicKey,
//		&priv2.PublicKey,
//		&priv3.PublicKey,
//	}
//	putData, err = json.Marshal(publicKeys)
//	if err != nil {
//		fmt.Errorf("Failed to json asset: %s", err)
//	}
//	err = json.Unmarshal(putData, &publicKeyss)
//	if err != nil {
//		fmt.Errorf("Failed to json asset: %s", err)
//	}
//
//	sigs := &RingSignature{}
//	// 签名消息
//	message := []byte("Hello, Ring Signature!")
//	sig, err := SignRing(message, priv, publicKeyss)
//	if err != nil {
//		fmt.Println("签名失败:", err)
//		return
//	}
//
//	putData, err = json.Marshal(sig)
//	if err != nil {
//		fmt.Errorf("Failed to json asset: %s", err)
//	}
//	err = json.Unmarshal(putData, &sigs)
//	if err != nil {
//		fmt.Errorf("Failed to json asset: %s", err)
//	}
//
//	// 验证签名
//	valid := VerifyRing(message, sigs)
//	fmt.Printf("签名验证结果: %v\n", valid) // 应输出 true
//}