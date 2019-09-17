package common

import "bytes"

// 对称密码， 分组加密，最后一组有需要填充数据的情况，如：cbc模式
func PaddingLastGroup(plainText []byte, blockSize int) []byte {
	var (
		padNum   int
		char     []byte
		newPlain []byte
		newText  []byte
	)
	padNum = blockSize - len(plainText)%blockSize
	char = []byte{
		byte(padNum),
	}

	newPlain = bytes.Repeat(char, padNum)

	newText = append(plainText, newPlain...)
	return newText
}

func UnPaddingLastGroup(plainText []byte) []byte {
	var (
		lastChar byte // 最后一个字节，该字节存储了尾部填充个数
		number   int  // 尾部填充个数
	)
	lastChar = plainText[len(plainText)-1]
	number = int(lastChar)
	return plainText[:len(plainText)-number]

}
