package sharePub

import (
	"crypto/aes"
	"crypto/cipher"
)

var iv []byte = []byte("1234567812345678")

func AesEncrypt(plainText, key []byte) []byte {
	var (
		cipherText []byte
		err        error
		block      cipher.Block
		stream     cipher.Stream
	)

	if block, err = aes.NewCipher(key); err != nil {
		panic(err)
	}

	stream = cipher.NewCTR(block, iv)
	cipherText = make([]byte, len(plainText))
	stream.XORKeyStream(cipherText, plainText)

	return cipherText
}

func AesDecrypt(cipherText, key []byte) []byte {
	var (
		err    error
		block  cipher.Block
		stream cipher.Stream
	)

	if block, err = aes.NewCipher(key); err != nil {
		panic(err)
	}

	stream = cipher.NewCTR(block, iv)

	stream.XORKeyStream(cipherText, cipherText)

	return cipherText
}
