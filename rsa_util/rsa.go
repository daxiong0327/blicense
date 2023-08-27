package rsa_util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

// GetKeys 生成公钥和私钥
func GetKeys(pairEncryptionKey string) error {
	//得到私钥
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	x509Privatekey := x509.MarshalPKCS1PrivateKey(privateKey)

	//创建一个用来保存私钥的以.pem结尾的文件
	fp, _ := os.Create(pairEncryptionKey + "_private.pem")
	defer fp.Close()

	//将私钥字符串设置到pem格式块中
	pemBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509Privatekey,
	}
	//转码为pem并输出到文件中
	if err := pem.Encode(fp, &pemBlock); err != nil {
		return err
	}

	//处理公钥,公钥包含在私钥中
	publicKey := privateKey.PublicKey
	//接下来的处理方法同私钥
	//通过x509标准将得到的ras私钥序列化为ASN.1 的 DER编码字符串
	x509PublicKey, _ := x509.MarshalPKIXPublicKey(&publicKey)
	pemPublicKey := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509PublicKey,
	}
	file, _ := os.Create(pairEncryptionKey + "_PublicKey.pem")
	defer file.Close()

	//转码为pem并输出到文件中
	if err := pem.Encode(file, &pemPublicKey); err != nil {
		return err
	}
	return nil
}

// RSAEncrypter 使用公钥进行加密
func RSAEncrypter(path string, msg []byte) ([]byte, error) {
	//首先从文件中提取公钥
	fp, _ := os.Open(path)
	defer fp.Close()
	//测量文件长度以便于保存
	fileInfo, _ := fp.Stat()
	buf := make([]byte, fileInfo.Size())
	if _, err := fp.Read(buf); err != nil {
		return nil, err
	}
	//下面的操作是与创建秘钥保存时相反的
	//pem解码
	block, _ := pem.Decode(buf)
	//x509解码,得到一个interface类型的pub
	pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
	//加密操作,需要将接口类型的pub进行类型断言得到公钥类型
	cipherText, _ := rsa.EncryptPKCS1v15(rand.Reader, pub.(*rsa.PublicKey), msg)
	return cipherText, nil
}

// RSADecrypter 使用私钥进行解密
func RSADecrypter(path string, cipherText []byte) ([]byte, error) {
	//同加密时，先将私钥从文件中取出，进行二次解码
	fp, _ := os.Open(path)
	defer fp.Close()
	fileInfo, _ := fp.Stat()
	buf := make([]byte, fileInfo.Size())

	if _, err := fp.Read(buf); err != nil {
		return nil, err
	}

	block, _ := pem.Decode(buf)
	PrivateKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	//二次解码完毕，调用解密函数
	afterDecrypter, _ := rsa.DecryptPKCS1v15(rand.Reader, PrivateKey, cipherText)
	return afterDecrypter, nil
}

// RsaSignWithSha256ByFile 使用私钥进行签名
func RsaSignWithSha256ByFile(data []byte, path string) ([]byte, error) {
	//解析私钥文件
	fp, _ := os.Open(path)
	defer fp.Close()
	fileInfo, _ := fp.Stat()
	buf := make([]byte, fileInfo.Size())
	if _, err := fp.Read(buf); err != nil {
		return nil, err
	}

	//生成签名
	signature, err := RsaSignWithSha256(data, buf)

	return signature, err
}

// RsaSignWithSha256ByBytes 使用私钥进行签名，从字节串中解析私钥
func RsaSignWithSha256ByBytes(data, privateBytes []byte) ([]byte, error) {
	//解析公钥文件
	signature, err := RsaSignWithSha256(data, privateBytes)

	return signature, err
}

// RsaSignWithSha256 使用私钥进行签名
func RsaSignWithSha256(data, privateBytes []byte) ([]byte, error) {
	//解析公钥文件
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)

	block, _ := pem.Decode(privateBytes)
	if block == nil {
		return nil, errors.New("rsa sign error")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("ParsePKIXPublicKey: " + err.Error())
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed)
	if err != nil {
		return nil, errors.New("VerifyPKCS1v15: " + err.Error())
	}

	return signature, nil
}

// RsaVisaSignWithSha256ByFile 使用公钥进行签名验证，公钥从文件中读取
func RsaVisaSignWithSha256ByFile(data, signData []byte, path string) (bool, error) {
	//解析公钥文件
	fp, _ := os.Open(path)
	defer fp.Close()
	fileInfo, _ := fp.Stat()
	buf := make([]byte, fileInfo.Size())
	if _, err := fp.Read(buf); err != nil {
		return false, err
	}
	//验签
	result, err := RsaVisaSignWithSha256(data, signData, buf)
	return result, err
}

// RsaVisaSignWithSha256ByByBytes 使用公钥进行验签，公钥不是从文件中读取，而是直接传入
func RsaVisaSignWithSha256ByByBytes(data, signData []byte, publicKeyBytes []byte) (bool, error) {

	result, err := RsaVisaSignWithSha256(data, signData, publicKeyBytes)
	return result, err
}

// RsaVisaSignWithSha256 使用公钥进行验签
func RsaVisaSignWithSha256(data, signData []byte, publicKeyBytes []byte) (bool, error) {
	//解析公钥文件
	block, _ := pem.Decode(publicKeyBytes)
	if block == nil {
		return false, errors.New("rsa very sign error")
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256(data)

	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetRsaPublicKey 获取公钥
func GetRsaPublicKey(path string) ([]byte, error) {
	//解析公钥文件
	fp, _ := os.Open(path)
	defer fp.Close()
	fileinfo, _ := fp.Stat()
	buf := make([]byte, fileinfo.Size())
	if _, err := fp.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
