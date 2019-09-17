package main

import (
	"fmt"
	sb "github.com/c0ding/ReviewCryptography/对称密码"
)

func main() {

	encrypt := sb.DesEncrypt([]byte("明文密码"), []byte("12345678"))
	decrypt := sb.DesDecrypt(encrypt, []byte("12345678"))
	fmt.Println(string(decrypt))

	encrypt = sb.Des3Encrypt([]byte("明文密码3"), []byte("123456781234567812345678"))

	decrypt = sb.Des3Decrypt(encrypt, []byte("123456781234567812345678"))

	fmt.Println(string(decrypt))
}
