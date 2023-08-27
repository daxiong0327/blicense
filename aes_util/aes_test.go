package aes_util

import (
	"github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestAes(t *testing.T) {
	originStr := "my test information"
	convey.Convey("test aes pair encryption", t, func() {
		//生成seaKey
		aesKey16, err := GenerateRandomCode(16)
		convey.So(err, convey.ShouldBeNil)

		//加密
		encryptStr, err := EncryptAes([]byte(originStr), aesKey16)
		convey.So(err, convey.ShouldBeNil)
		convey.So(encryptStr, convey.ShouldNotBeEmpty)

		//解密
		decryptStr, err := DecryptAes(encryptStr, aesKey16)
		convey.So(err, convey.ShouldBeNil)
		convey.So(decryptStr, convey.ShouldNotBeEmpty)
		convey.So(decryptStr, convey.ShouldEqual, originStr)
	})
}
