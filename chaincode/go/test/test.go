/*
 * Copyright IBM Corp All Rights Reserved
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/peer"
	paillier "github.com/roasbeef/go-go-gadget-paillier"
	"math/big"
	"math/rand"
	"strconv"
	ra "crypto/rand"
	"time"
)

type FileData struct {
	Id                  string `json:"id"`
	Filename            string `json:"filename"`
	FileDetail          string `json:"filedetail"`
	FileHash            string `json:"fileHash"`
	CreateDate          string `json:"createDate"`
	Username            string `json:"username"`
	Times               string `json:"times"`
	Card                string `json:"card"`
	User                []string `json:"user"`
	Filepath            string `json:"filepath"`
	IpfsHash            string `json:"ipfsHash"`
	Time                string `json:"time"`
	Date                string `json:"date"`
	End                  string `json:"end"`
	Money               string `json:"money"`
	Money1               string `json:"money1"`
	TransferDate        string `json:"transferdate"`
	Flag                string `json:"flag"`
	Tmp                string `json:"tmp"`
}
type Transaction struct {
	Id                  string `json:"id"`
	Filename            string `json:"filename"`
	Date                string `json:"date"`
	Username            string `json:"username"`
	User                string `json:"user"`
	Username1           string `json:"username1"`
	User1               string `json:"user1"`
	Money               string `json:"money"`
	Money1               string `json:"money1"`
	FileHash               string `json:"fileHash"`
	Flag                string `json:"flag"`
}
type User struct {
	Id             string
	Money          string
}
// 环签名结构
type RingSignature struct {
	PublicKeys []*ecdsa.PublicKey // 环中的公钥集合
	C          *big.Int           // 挑战值
	S          []*big.Int         // 签名值集合
}
// SimpleAsset implements a simple chaincode to manage an asset
type SimpleAsset struct {
}

// Init is called during chaincode instantiation to initialize any
// data. Note that chaincode upgrade also calls this function to reset
// or to migrate data.
func (t *SimpleAsset) Init(stub shim.ChaincodeStubInterface) peer.Response {
	// Get the args from the transaction proposal
	return shim.Success(nil)
}

// Invoke is called per transaction on the chaincode. Each transaction is
// either a 'get' or a 'set' on the asset created by Init function. The Set
// method may create a new asset by specifying a new key-value pair.
func (t *SimpleAsset) Invoke(stub shim.ChaincodeStubInterface) peer.Response {
	// Extract the function and args from the transaction proposal
	fn, args := stub.GetFunctionAndParameters()

	var result string
	var err error
	if fn == "setFileData" {
		err = setFileData(stub, args)
	} else if fn == "getFileData" {
		result, err = getFileData(stub, args)
	} else if fn == "getFileDetail" {
		result, err = getFileDetail(stub, args)
	} else if fn == "getOwnerFileDetail" {
		result, err = getOwnerFileDetail(stub, args)
	} else if fn == "setTransaction" {
		result, err = setTransaction(stub, args)
	} else if fn == "setMoney" {
		result, err = setMoney(stub, args)
	} else if fn == "getMoney" {
		result, err = getMoney(stub, args)
	} else if fn == "getTransaction" {
		result, err = getTransaction(stub, args)
	} else if fn == "set" {
		result, err = set(stub, args)
	} else if fn == "delete" {
		result, err = delete(stub, args)
	} else if fn == "setKey" {
		result, err = setKey(stub, args)
	}
	if err != nil {
		return shim.Error(err.Error())
	}

	// Return the result as success payload
	return shim.Success([]byte(result))
}

// Set stores the asset (both key and value) on the ledger. If the key exists,
// it will override the value with the new one
// 将对象序列化后保存至账本中
func setFileData(stub shim.ChaincodeStubInterface, args []string) (error) {
	var fileData FileData
	var fileDatas []FileData
	err := json.Unmarshal([]byte(args[0]), &fileData)
	if err != nil {
		return fmt.Errorf("Failed to json asset: %s", err)
	}
	assetJSON, err := stub.GetState("FileData")
	if err != nil {
		return fmt.Errorf("Failed to set asset: %s", err)
	}
	if assetJSON == nil {
		fileDatas = append(fileDatas,fileData)
	}else {
		err = json.Unmarshal(assetJSON, &fileDatas)
		if err != nil {
			return fmt.Errorf("Failed to json asset: %s", err)
		}
		fileDatas = append(fileDatas,fileData)
	}
	putData, err := json.Marshal(fileDatas)
	if err != nil {
		return fmt.Errorf("Failed to json asset: %s", err)
	}
	err = stub.PutState("FileData", putData)
	if err != nil {
		return fmt.Errorf("Failed to set asset: %s", err)
	}
	return nil
}
// 查询对应的值
func getFileDetail(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	id := args[0]
	var fileDatas []FileData
	assetJSON, err := stub.GetState("FileData")
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &fileDatas)
	if err != nil {
		return "",fmt.Errorf("Failed to json asset: %s", err)
	}
	for _, fd := range fileDatas{
		if id == fd.Id {
			putData, err := json.Marshal(fd)
			if err != nil {
				return "", fmt.Errorf("Failed to json asset: %s", err)
			}
			return string(putData), nil
		}
	}
	return "", fmt.Errorf("Failed to get asset: %s", err)
}
// 查询对应的值
func getOwnerFileDetail(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	id := args[0]
	var fileDatas []FileData
	assetJSON, err := stub.GetState(args[1])
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &fileDatas)
	if err != nil {
		return "",fmt.Errorf("Failed to json asset: %s", err)
	}
	for _, fd := range fileDatas{
		if id == fd.Id {
			putData, err := json.Marshal(fd)
			if err != nil {
				return "", fmt.Errorf("Failed to json asset: %s", err)
			}
			return string(putData), nil
		}
	}
	return "", fmt.Errorf("Failed to get asset: %s", err)
}

func getFileData(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	assetJSON, err := stub.GetState("FileData")
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	return string(assetJSON), nil
}


func setTransaction(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	// 从参数中获取用户ID、商品ID、金额和签名
	uid := args[0]
	cid := args[1]
	money := args[2]
	sig := args[3]

	publicKeys := []*ecdsa.PublicKey{}
	priv := &ecdsa.PrivateKey{}
	// 获取用户的私钥
	assetJSON, err := stub.GetState("K-"+uid)
	err = json.Unmarshal(assetJSON, &priv)
	if err != nil {
		fmt.Errorf("Failed to json1 asset: %s", err)
	}

	// 获取并更新环签名
	assetJSON, err = stub.GetState("Ring")
	err = json.Unmarshal(assetJSON, &publicKeys)
	if err != nil {
		fmt.Errorf("Failed to json1 asset: %s", err)
	}
	publicKeys = append(publicKeys, &priv.PublicKey)
	putData, err := json.Marshal(publicKeys)
	if err != nil {
		return "", fmt.Errorf("Failed to json2 asset: %s", err)
	}
	err = stub.PutState("Ring", putData)
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}

	// 设置签名
	err = stub.PutState(uid+"-sig-"+cid, []byte(sig))
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}



	// 更新用户资金
	var user User
	assetJSON, err = stub.GetState("F-"+cid)
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	if assetJSON == nil {
	    // 如果用户资金记录不存在，则创建新的记录
		user.Id = uid
		user.Money = money
		putData, err = json.Marshal(user)
		if err != nil {
			return "", fmt.Errorf("Failed to json2 asset: %s", err)
		}
		err = stub.PutState("F-"+cid, putData)
		if err != nil {
			return "",fmt.Errorf("Failed to set asset: %s", err)
		}
	}else {
	    // 如果用户资金记录已存在，则进行加密操作
		err = json.Unmarshal(assetJSON, &user)
		if err != nil {
			return "",fmt.Errorf("Failed to json1 asset: %s", err)
		}
		priv, _ := paillier.GenerateKey(ra.Reader, 128)
		// 验证核心参数
		old, _ := strconv.Atoi(user.Money)
		first := new(big.Int).SetInt64(int64(old))
		c1, _ := paillier.Encrypt(&priv.PublicKey, first.Bytes())

		rand.Seed(time.Now().UnixNano())
		ra1 := rand.Int63n(100)
		ra2 := rand.Int63n(100)

		//input := new(big.Int).SetInt64(int64(int64(adata)*ra1 + ra2))
		news, _ := strconv.Atoi(money)
		input := new(big.Int).SetInt64(int64(int64(news)*ra1 + ra2))
		cinput, _ := paillier.Encrypt(&priv.PublicKey, input.Bytes())

		mulE15and10 := paillier.Mul(&priv.PublicKey, c1, new(big.Int).SetInt64(int64(ra1)).Bytes())
		cy, _ := paillier.Encrypt(&priv.PublicKey, new(big.Int).SetInt64(int64(ra2)).Bytes())
		cinput2 := paillier.AddCipher(&priv.PublicKey, cy, mulE15and10)

		minput, _ := paillier.Decrypt(priv, cinput);
		minput2, _ := paillier.Decrypt(priv, cinput2);

		if new(big.Int).SetBytes(minput).Int64() > new(big.Int).SetBytes(minput2).Int64() {
			user.Id = uid
			user.Money = money
			putData, err = json.Marshal(user)
			if err != nil {
				return "", fmt.Errorf("Failed to json2 asset: %s", err)
			}
			err = stub.PutState("F-"+cid, putData)
			if err != nil {
				return "",fmt.Errorf("Failed to set asset: %s", err)
			}
		}
	}

	// 更新用户列表
	var lists []string
	assetJSON, err = stub.GetState("L-"+cid)
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	if assetJSON == nil {
		lists = append(lists,uid)
	}else {
		err = json.Unmarshal(assetJSON, &lists)
		if err != nil {
			return "",fmt.Errorf("Failed to json1 asset: %s", err)
		}
		lists = append(lists, uid)
	}
	putData, err = json.Marshal(lists)
	if err != nil {
		return "", fmt.Errorf("Failed to json2 asset: %s", err)
	}
	err = stub.PutState("L-"+cid, putData)
	if err != nil{
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}

    // 更新文件数据
	var fileDatas []FileData
	var nfileDatas []FileData
	assetJSON, err = stub.GetState("FileData")
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &fileDatas)
	if err != nil {
		return "",fmt.Errorf("Failed to json asset: %s", err)
	}
	for _, fd := range fileDatas{
		if cid == fd.Id {
			//set user buy
			assetJSON, err = stub.GetState("Tmp-"+uid)
			if err != nil {
				return "", fmt.Errorf("Failed to get asset: %s", err)
			}
			if assetJSON == nil {
				nfileDatas = append(nfileDatas,fd)
			}else {
				err = json.Unmarshal(assetJSON, &nfileDatas)
				if err != nil {
					return "",fmt.Errorf("Failed to json1 asset: %s", err)
				}
				nfileDatas = append(nfileDatas, fd)
			}
			putData, err := json.Marshal(nfileDatas)
			if err != nil {
				return "", fmt.Errorf("Failed to json2 asset: %s", err)
			}
			err = stub.PutState("Tmp-"+uid, putData)
			if err != nil{
				return "",fmt.Errorf("Failed to set asset: %s", err)
			}
			return "success",nil
		}
	}

	return "fail", nil
}

func setMoney(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	if args[2] == "init"{
		err := stub.PutState(args[0], []byte(args[1]))
		if err != nil {
			return "",fmt.Errorf("Failed to set asset: %s", err)
		}
		return "init success", nil
	}
	value, err := stub.GetState(args[0])
	if err != nil {
		return "",fmt.Errorf("Failed to get asset: %s", err)
	}
	time.Sleep(10)
	int1 ,err := strconv.ParseFloat(string(value),64)
	int2 ,err := strconv.ParseFloat(args[1],64)
	int3 := int1 + int2
	if args[2] == "down"{
		int3 = int1 - int2
	}
	money := strconv.FormatFloat(int3, 'f', 2, 64)
	err = stub.PutState(args[0], []byte(money))
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}
	return money, nil
}
func getMoney(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	value, err := stub.GetState(args[0])
	if err != nil {
		return "",fmt.Errorf("Failed to get asset: %s", err)
	}
	int1 ,err := strconv.ParseFloat(string(value),64)
	int2 ,err := strconv.ParseFloat(args[1],64)
	if int1 < int2 {
		return string(value), fmt.Errorf("not enough")
	}
	return string(value), nil
}
func getTransaction(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	assetJSON, err := stub.GetState(args[0])
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	return string(assetJSON), nil
}
func setKey(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	err := stub.PutState(args[0], []byte(args[1]))
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}
	return "success", nil
}
func set(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	id := args[0]
	var fileDatas []FileData
	var nfileDatas []FileData
	assetJSON, err := stub.GetState("FileData")
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &fileDatas)
	if err != nil {
		return "",fmt.Errorf("Failed to json asset: %s", err)
	}
	for _, fd := range fileDatas{
		if id == fd.Id {
			fd.Money = args[1]
			fd.Tmp = fd.Flag
			fd.Flag = "竞拍中"
			fd.TransferDate = args[2]
			fd.End = args[3]
		}
		nfileDatas = append(nfileDatas, fd)
	}
	putData, err := json.Marshal(nfileDatas)
	if err != nil {
		return "", fmt.Errorf("Failed to json asset: %s", err)
	}
	err = stub.PutState("FileData", putData)
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}
	return "success", nil
}
func delete(stub shim.ChaincodeStubInterface, args []string) (string, error) {
	id := args[0]
	var fileDatas []FileData
	var nfileDatas []FileData
	var newFileDatas []FileData

	var fileData FileData
	var user User
	sig := &RingSignature{}
	publicKeys := []*ecdsa.PublicKey{}
	assetJSON, err := stub.GetState("FileData")
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &fileDatas)
	if err != nil {
		return "",fmt.Errorf("Failed to json asset: %s", err)
	}
	assetJSON, err = stub.GetState("F-"+id)
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &user)
	if err != nil {
		return "",fmt.Errorf("Failed to json asset: %s", err)
	}

	//verify
	assetJSON, err = stub.GetState(user.Id+"-sig-"+id)
	err = json.Unmarshal(assetJSON, &sig)
	if err != nil {
		return "",fmt.Errorf("Failed to json1 asset: %s", err)
	}

	assetJSON, err = stub.GetState("Ring")
	err = json.Unmarshal(assetJSON, &publicKeys)
	if err != nil {
		fmt.Errorf("Failed to json1 asset: %s", err)
	}

	putData, err := json.Marshal(user)
	valid := VerifyRing([]byte(MD5(string(putData))), sig)
	if valid == false{
		return "",fmt.Errorf("Failed to VerifyRing: %s", err)
	}

	for _, fd := range fileDatas{
		if id == fd.Id {
			fd.Money1 = user.Money
			fd.Flag = "已结束"
			fd.TransferDate = ""
			fd.End = args[1]
			fileData = fd
		}
		nfileDatas = append(nfileDatas, fd)
	}
	putData, err = json.Marshal(nfileDatas)
	if err != nil {
		return "", fmt.Errorf("Failed to json asset: %s", err)
	}
	err = stub.PutState("FileData", putData)
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}

	//set user
	assetJSON, err = stub.GetState("F-"+user.Id)
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	if assetJSON == nil {
		newFileDatas = append(newFileDatas,fileData)
	}else {
		err = json.Unmarshal(assetJSON, &newFileDatas)
		if err != nil {
			return "",fmt.Errorf("Failed to json1 asset: %s", err)
		}
		newFileDatas = append(newFileDatas, fileData)
	}
	putData, err = json.Marshal(newFileDatas)
	if err != nil {
		return "", fmt.Errorf("Failed to json2 asset: %s", err)
	}
	err = stub.PutState("F-"+user.Id, putData)
	if err != nil {
		return "",fmt.Errorf("Failed to set asset: %s", err)
	}

	//money
	a := []string{user.Id, fileData.Money1, "down"}
	_, err = setMoney(stub, a)
	if err != nil {
		return "",fmt.Errorf("Failed to setMoney asset: %s", err)
	}


	//update
	var lists []string
	assetJSON, err = stub.GetState("L-"+id)
	if err != nil {
		return "", fmt.Errorf("Failed to get asset: %s", err)
	}
	err = json.Unmarshal(assetJSON, &lists)
	if err != nil {
		return "",fmt.Errorf("Failed to json1 asset: %s", err)
	}
	for _,l := range lists{
		var fd FileData
		assetJSON, err = stub.GetState("Tmp-"+l)
		err = json.Unmarshal(assetJSON, &fd)
		if err != nil {
			return "",fmt.Errorf("Failed to json1 asset: %s", err)
		}
		if l == user.Id{
			fd.Flag = "已结束，恭喜中标"
		}else {
			fd.Flag = "已结束，未中标"
		}
		putData, err = json.Marshal(fd)
		if err != nil {
			return "", fmt.Errorf("Failed to json2 asset: %s", err)
		}
		err = stub.PutState("Tmp-"+l, putData)
		if err != nil {
			return "",fmt.Errorf("Failed to set asset: %s", err)
		}
	}

	return "success", nil
}
//将字符串进行md5加密
func MD5(str string) string {
	data := []byte(str) //切片
	has := md5.Sum(data)
	md5str := fmt.Sprintf("%x", has) //将[]byte转成16进制
	return md5str
}


// 生成环签名
func SignRing(message []byte, privKey *ecdsa.PrivateKey, publicKeys []*ecdsa.PublicKey) (*RingSignature, error) {
	n := len(publicKeys)
	if n == 0 {
		return nil, fmt.Errorf("至少需要一个公钥")
	}

	// 1. 计算消息哈希
	hash := sha256.Sum256(message)

	// 2. 找到签名者在环中的位置
	k := -1
	for i, pk := range publicKeys {
		if pk.X.Cmp(privKey.X) == 0 && pk.Y.Cmp(privKey.Y) == 0 {
			k = i
			break
		}
	}
	if k == -1 {
		return nil, fmt.Errorf("私钥未在公钥列表中")
	}

	curve := elliptic.P256()
	params := curve.Params()
	//nMinus1 := big.NewInt(int64(n - 1))

	// 3. 初始化参数
	s := make([]*big.Int, n)
	c := make([]*big.Int, n)

	// 4. 生成随机数v (实际应为k+1的挑战)
	v, _ := ra.Int(ra.Reader, params.N)
	c[(k+1)%n] = new(big.Int).SetBytes(hash[:])
	c[(k+1)%n].Mod(c[(k+1)%n], params.N)

	// 5. 前向计算环
	i := (k + 1) % n
	for i != k {
		// 生成随机s[i]
		s[i], _ = ra.Int(ra.Reader, params.N)

		// 计算下一挑战
		sGx, sGy := curve.ScalarBaseMult(s[i].Bytes())
		cPx, cPy := curve.ScalarMult(publicKeys[i].X, publicKeys[i].Y, c[i].Bytes())
		sumX, sumY := curve.Add(sGx, sGy, cPx, cPy)

		hashInput := append(sumX.Bytes(), sumY.Bytes()...)
		hashInput = append(hashInput, message...)
		nextHash := sha256.Sum256(hashInput)

		next := (i + 1) % n
		c[next] = new(big.Int).SetBytes(nextHash[:])
		c[next].Mod(c[next], params.N)

		i = (i + 1) % n
	}

	// 6. 关闭环
	s[k] = new(big.Int).Sub(v, new(big.Int).Mul(c[k], privKey.D))
	s[k].Mod(s[k], params.N)

	return &RingSignature{
		PublicKeys: publicKeys,
		C:          c[0],
		S:          s,
	}, nil
}

// 验证环签名
func VerifyRing(message []byte, sig *RingSignature) bool {
	n := len(sig.PublicKeys)
	if n == 0 {
		return false
	}

	curve := elliptic.P256()
	params := curve.Params()
	c := make([]*big.Int, n)
	c[0] = new(big.Int).Set(sig.C)

	// 重构挑战链
	for i := 0; i < n; i++ {
		// 计算sG + cP
		sGx, sGy := curve.ScalarBaseMult(sig.S[i].Bytes())
		cPx, cPy := curve.ScalarMult(sig.PublicKeys[i].X, sig.PublicKeys[i].Y, c[i].Bytes())
		sumX, sumY := curve.Add(sGx, sGy, cPx, cPy)

		// 计算下一挑战
		hashInput := append(sumX.Bytes(), sumY.Bytes()...)
		hashInput = append(hashInput, message...)
		nextHash := sha256.Sum256(hashInput)

		next := (i + 1) % n
		if next == 0 {
			break
		}
		c[next] = new(big.Int).SetBytes(nextHash[:])
		c[next].Mod(c[next], params.N)
	}

	// 验证环闭合
	return c[0].Cmp(sig.C) == 0
}
// main function starts up the chaincode in the container during instantiate
func main() {
	if err := shim.Start(new(SimpleAsset)); err != nil {
		fmt.Printf("Error starting SimpleAsset chaincode: %s", err)
	}
}
