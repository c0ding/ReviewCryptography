package sharePub

import (
	"crypto/cipher"
	"crypto/des"
	"github.com/c0ding/ReviewCryptography/对称密码/common"
)

func Des3Encrypt(plainText, key []byte) []byte {
	var (
		cipherText []byte
		err        error
		block      cipher.Block
		newText    []byte
		blockMode  cipher.BlockMode
		iv         []byte = []byte("12345678")
	)
	//1
	if block, err = des.NewTripleDESCipher(key); err != nil {
		panic(err)
	}
	//2
	newText = common.PaddingLastGroup(plainText, block.BlockSize())
	//3
	blockMode = cipher.NewCBCEncrypter(block, iv)
	//4
	cipherText = make([]byte, len(newText))
	blockMode.CryptBlocks(cipherText, newText)
	//blockMode.CryptBlocks(newText, newText)
	return cipherText
}

func Des3Decrypt(cipherText, key []byte) []byte {
	var (
		plainText []byte
		err       error
		block     cipher.Block

		blockMode cipher.BlockMode
		iv        []byte = []byte("12345678")
	)

	if block, err = des.NewTripleDESCipher(key); err != nil {
		panic(err)
	}

	blockMode = cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(cipherText, cipherText)

	plainText = common.UnPaddingLastGroup(cipherText)
	return plainText
}
