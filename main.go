package main

import (
	"fmt"
	sb "github.com/c0ding/ReviewCryptography/对称密码"
	"github.com/c0ding/ReviewCryptography/消息认证码"
	"github.com/c0ding/ReviewCryptography/common"
	"github.com/c0ding/ReviewCryptography/数字签名"
	"github.com/c0ding/ReviewCryptography/散列函数"
	pc "github.com/c0ding/ReviewCryptography/非对称密码"

)

func main() {

	encrypt := sb.DesEncrypt([]byte("明文密码des-cbc"), []byte("12345678"))
	decrypt := sb.DesDecrypt(encrypt, []byte("12345678"))
	fmt.Println(string(decrypt))

	encrypt = sb.Des3Encrypt([]byte("明文密码 3des-cbc"), []byte("123456781234567812345678"))
	decrypt = sb.Des3Decrypt(encrypt, []byte("123456781234567812345678"))
	fmt.Println(string(decrypt))

	encrypt = sb.AesEncrypt([]byte("明文密码 aes-ctr"), []byte("1234567812345678"))
	decrypt = sb.AesDecrypt(encrypt, []byte("1234567812345678"))
	fmt.Println(string(decrypt))


	pc.GenerateRsaKey(4096)
	src := []byte("明文明文明文明文明文明文明文明文明文明文,明,文")
	cipherText := pc.RsaEncrypt(src, common.Public)
	plainText := pc.RsaDecrypt(cipherText, common.Private)
	fmt.Println(string(plainText))

	hash := hashfunc.Hash([]byte("erwe士大夫撒的是"))
	fmt.Println(hash)


	key := []byte("123456781234")
	ha1 := mac.GenerateHmac(src,key)
	bl := mac.VerifyHmac(src,key,ha1)
	fmt.Println("消息认证码：",bl)

	sigText := sign.SignatureRSA(src, common.Private)
	bl = sign.VerifyRSA(src, sigText, common.Public)
	fmt.Println("rsa签名验证结果:",bl)
}

