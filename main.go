package main

import (
	"fmt"
	sb "github.com/c0ding/ReviewCryptography/对称密码"
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
}
