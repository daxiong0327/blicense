package aes_util

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// GenerateRandomCode 生成长度为 length 的 aes key
func GenerateRandomCode(length int) (string, error) {
	result := make([]byte, length)
	_, err := rand.Read(result)
	if err != nil {
		return "", err
	}

	for i, b := range result {
		result[i] = charset[b%byte(len(charset))]
	}

	return string(result), nil
}

// EncryptAes 加密
func EncryptAes(origData []byte, key string) (string, error) {
	// 转成字节数组
	k := []byte(key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	origData = padding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, k)
	blockMode.CryptBlocks(origData, origData)
	return base64.StdEncoding.EncodeToString(origData), nil
}

// DecryptAes 解密
func DecryptAes(cryted string, key string) (string, error) {
	// 转成字节数组
	crytedByte, _ := base64.StdEncoding.DecodeString(cryted)
	k := []byte(key)

	block, err := aes.NewCipher(k)
	if err != nil {
		return "", err
	}
	blockMode := cipher.NewCBCDecrypter(block, k)
	blockMode.CryptBlocks(crytedByte, crytedByte)
	crytedByte = unPadding(crytedByte)
	return string(crytedByte), nil
}

// padding 填充数据
func padding(src []byte, blockSize int) []byte {
	padNum := blockSize - len(src)%blockSize
	pad := bytes.Repeat([]byte{byte(padNum)}, padNum)
	return append(src, pad...)
}

// unPadding 去掉填充数据
func unPadding(src []byte) []byte {
	n := len(src)
	unPadNum := int(src[n-1])
	return src[:n-unPadNum]
}
