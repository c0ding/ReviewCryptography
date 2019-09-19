package mac

import (
	"hash"
	"crypto/hmac"
	"crypto/sha256"
)

func GenerateHmac(plainText, key []byte)(hashText []byte)  {
	var (
		myhash hash.Hash
	)
	myhash = hmac.New(sha256.New,key)
	myhash.Write(plainText)
	hashText = myhash.Sum(nil)
	return
}

func VerifyHmac(plainText , key , hashText []byte)bool  {
	var (
		myhash hash.Hash
		vHashText []byte
	)
	myhash = hmac.New(sha256.New,key)
	myhash.Write(plainText)
	vHashText = myhash.Sum(nil)
	return hmac.Equal(hashText,vHashText)
}