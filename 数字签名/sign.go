package sign

import (
	"os"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"hash"
	"crypto/rand"
	"crypto"
	"crypto/sha512"
	"errors"
)

func SignatureRSA(plainText []byte,priFileName string) (sigText []byte) {
	var (
		buf []byte
		block *pem.Block
		privateKey *rsa.PrivateKey
		err error
		myhash hash.Hash
		myhashText []byte
	)
	buf  = keyByFile(priFileName)
	//使用pem对数据解码
	block, _ = pem.Decode(buf)
	//x509将数据解析成私钥结构体 -> 得到了私钥
	if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic(err)
	}
	//明文生成 散列值
	myhash = sha512.New()
	myhash.Write(plainText)
	myhashText = myhash.Sum(nil)
	if sigText, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, myhashText); err != nil {
		panic(err)
	}
	return
}

func VerifyRSA(plainText, sigText []byte, pubFileName string)bool  {
	var (
		buf []byte
		block *pem.Block
		publicKeyInterface interface{}
		err error
		ok bool
		publicKey *rsa.PublicKey
		myhash hash.Hash
		myhashText []byte

	)
	buf  = keyByFile(pubFileName)

	block, _ = pem.Decode(buf)
	if publicKeyInterface, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		panic(err)
	}

	if publicKey,ok = publicKeyInterface.(*rsa.PublicKey);!ok  {
		panic(errors.New("公钥解析错误"))
	}

	myhash = sha512.New()
	myhash.Write(plainText)
	myhashText = myhash.Sum(nil)
	if err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA512, myhashText, sigText); err != nil {
		return false
	}else {
		return true
	}


}
func keyByFile(fileName string)[] byte  {
	//1. 打开磁盘的私钥文件
	file, err := os.Open(fileName)
	if err != nil {
		panic(err)
	}
	//2. 将私钥文件中的内容读出
	info, err := file.Stat()
	if err != nil {
		panic(err)
	}
	buf := make([]byte, info.Size())
	file.Read(buf)
	file.Close()
	return buf
}