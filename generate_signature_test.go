package blicense

import (
	"github.com/smartystreets/goconvey/convey"
	"os"
	"testing"
)

func TestNewCertificateInfoByPrivateFile(t *testing.T) {
	convey.Convey("NewCertificateInfoByPrivateFile", t, func() {
		testAuth := &AuthorizationInfo{
			Issuer:       "issuer",
			AppName:      "license",
			NetworkCard:  "en0",
			Ip:           "127.0.0.1",
			Mac:          "mac",
			CustomerInfo: "customerInfo",
			Duration:     1,
		}

		err := NewCertificateInfoByPrivateFile(testAuth, "./cache_cert/w5bEHDdGvCxoFahB_PublicKey.pem")
		convey.So(err, convey.ShouldBeNil)
		//校验通过时，应该在cache_cert 中生成对应ip的证书信息，以及err为nil
	})
}

func TestNewCertificateInfoByPrivateBytes(t *testing.T) {
	convey.Convey("NewCertificateInfoByPrivateBytes", t, func() {
		testAuth := &AuthorizationInfo{
			Issuer:       "issuer",
			AppName:      "license",
			NetworkCard:  "en0",
			Ip:           "127.0.0.1",
			Mac:          "mac",
			CustomerInfo: "customerInfo",
			Duration:     1,
		}
		fp, _ := os.Open("./cache_cert/w5bEHDdGvCxoFahB_private.pem")
		defer fp.Close()
		fileInfo, _ := fp.Stat()
		buf := make([]byte, fileInfo.Size())
		_, err := fp.Read(buf)
		convey.So(err, convey.ShouldBeNil)
		cerInfo, err := NewCertificateInfoByPrivateBytes(testAuth, buf)
		convey.So(err, convey.ShouldBeNil)
		convey.So(cerInfo, convey.ShouldNotBeNil)

	})
}
