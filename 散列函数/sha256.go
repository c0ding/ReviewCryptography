package hashfunc

import (
	"crypto/sha256"
	"hash"
	"encoding/hex"
)

func Hash(plainText []byte)string  {
	var (
		myHash hash.Hash
		res []byte
		myStr string
	)
	myHash = sha256.New()

	//myHash.Write([]byte("明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文明文"))
	myHash.Write(plainText)
	res = myHash.Sum(nil)
	myStr = hex.EncodeToString(res)
	return myStr
}
