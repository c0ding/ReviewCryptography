package pubKeyCrypto

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"fmt"
	"github.com/c0ding/ReviewCryptography/common"
)



// 生成rsa 密钥对，保存到磁盘中
func GenerateRsaKey(keySize int) {
	var (
		privateKey *rsa.PrivateKey
		err error
		derText []byte
		block pem.Block
		file *os.File

		publicKey rsa.PublicKey
		derstream []byte
	)

	if privateKey, err = rsa.GenerateKey(rand.Reader, keySize); err != nil {
		panic(err)
	}
	derText = x509.MarshalPKCS1PrivateKey(privateKey)
	block = pem.Block{
		Type:"rsa private key",
		Bytes:derText,
	}
	if file, err = os.Create(common.Private ); err != nil {
		panic(err)
	}
	pem.Encode(file, &block)
	file.Close()


	publicKey = privateKey.PublicKey
	if derstream, err = x509.MarshalPKIXPublicKey(&publicKey); err != nil {
		panic(err)
	}
	block = pem.Block{
		Type:"rsa public key",
		Bytes:derstream,
	}
	if file, err = os.Create(common.Public); err != nil {
		panic(err)
	}
	pem.Encode(file,&block)
	file.Close()
}

func RsaEncrypt(plainText []byte, fileName string) []byte {

	var (
		file *os.File
		fileInfo os.FileInfo
		err error
		buf []byte
		block *pem.Block
		pub interface{}
		pubKey *rsa.PublicKey
		cipherText []byte
		ok bool
	)
	if file, err = os.Open(fileName); err != nil {
		panic(err)
	}

	if fileInfo, err = file.Stat(); err != nil {
		panic(err)
	}
	buf = make([]byte, fileInfo.Size())
	file.Read(buf)
	file.Close()
	block, _ = pem.Decode(buf)

	if pub, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		fmt.Println("11111出错")
		panic(err)
	}
	if pubKey, ok = pub.(*rsa.PublicKey); !ok  {
		fmt.Println("出错")
		panic(err)
	}
	if cipherText, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText); err != nil {
		panic(err)
	}
	return cipherText

}

func RsaDecrypt(cipherText []byte, fileName string) []byte {
	var (
		err error
		file *os.File
		fileInfo os.FileInfo
		buf []byte
		block *pem.Block
		privateKey *rsa.PrivateKey
		plainText []byte
	)

	if file, err = os.Open(fileName); err != nil {
		panic(err)
	}
	if fileInfo, err = file.Stat(); err != nil {
		panic(err)
	}
	buf = make([]byte, fileInfo.Size())
	file.Read(buf)
	file.Close()
	block, _ = pem.Decode(buf)
	if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		panic(err)
	}
	if plainText, err = rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText); err != nil {
		panic(err)
	}
	return plainText
}
