package rsa_util

import (
	"blicense/aes_util"
	"github.com/smartystreets/goconvey/convey"
	"testing"
)

var pairEncryptionKey string

func init() {
	var err error
	pairEncryptionKey, err = aes_util.GenerateRandomCode(16)
	if err != nil {
		print("generate random code error:", err.Error())
	}
}

// 测试私钥加密，公钥解密
func TestRsaPvEPuD(t *testing.T) {
	originStr := "my test information"

	convey.Convey("test ras non pair encryption", t, func() {
		convey.So(pairEncryptionKey, convey.ShouldNotBeEmpty)
		//生成非对成加密的公钥、私钥
		err := GetKeys(pairEncryptionKey)
		convey.So(err, convey.ShouldBeNil)
		//公钥加密
		cipherText, err := RSAEncrypter("./"+pairEncryptionKey+"_PublicKey.pem", []byte(originStr))
		convey.So(err, convey.ShouldBeNil)
		//私钥解密
		afterDecrypter, err := RSADecrypter("./"+pairEncryptionKey+"_private.pem", cipherText)
		convey.So(err, convey.ShouldBeNil)

		decrypterStr := string(afterDecrypter)
		convey.So(originStr, convey.ShouldEqual, decrypterStr)
	})
}

// 测试验签
func TestVerificationSignature(t *testing.T) {
	originStr := "my test information"

	convey.Convey("test ras non pair verification signature", t, func() {
		convey.So(pairEncryptionKey, convey.ShouldNotBeEmpty)
		//生成非对称密钥对，进行签名认证
		err := GetKeys(pairEncryptionKey)
		convey.So(err, convey.ShouldBeNil)
		//私钥生成签名
		sign, err := RsaSignWithSha256ByFile([]byte(originStr), "./"+pairEncryptionKey+"_private.pem")
		convey.So(err, convey.ShouldBeNil)
		//验证签名
		result, err := RsaVerySignWithSha256ByFile([]byte(originStr), sign, "./"+pairEncryptionKey+"_PublicKey.pem")
		convey.So(err, convey.ShouldBeNil)
		convey.So(result, convey.ShouldBeTrue)

	})
}
