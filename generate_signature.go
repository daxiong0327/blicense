package blicense

import (
	"blicense/aes_util"
	"blicense/rsa_util"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	LicenseCache = "./cache_cert"
	PrivateKey   = "-----BEGIN PRIVATE KEY-----\nMIIEowIB"
)

type AuthorizationInfo struct {
	Issuer       string `json:"issuer"`       //签发人
	AppName      string `json:"appName"`      //应用名
	NetworkCard  string `json:"networkCard"`  //网卡名称
	Ip           string `json:"ip"`           //授权者ip
	Mac          string `json:"mac"`          //授权者ip地址
	CustomerInfo string `json:"customerInfo"` //被授权人
	Duration     uint   `json:"duration"`     //持续时间 单位天
	NotBefore    int64  //起始时间
	NotAfter     int64  //终止时间
	//SerialNumber string `json:"serialNumber"` //授权者主板序列号 暂不启用
}

type ResponseInfo struct {
	ErrorInfo        []string `json:"errorInfo"`
	DownloadCertPath []string `json:"downloadCertPath"`
}

// serializationAuthorization 反序列化授权信息
func serializationAuthorization(authByte []byte) ([]*AuthorizationInfo, error) { //nolint:unused

	var authInfo []*AuthorizationInfo
	if err := json.Unmarshal(authByte, &authInfo); err != nil {
		return nil, errors.New(err.Error())
	}

	return authInfo, nil
}

// ApplicationCertificate 申请证书，返回证书路径（此处使用的特定的私钥，实际使用时需要替换，为自己的私钥）
func ApplicationCertificate(rw http.ResponseWriter, r *http.Request) {

	//解析请求信息
	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	authInfo, err := serializationAuthorization(bytes)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	responseInfo := &ResponseInfo{}
	for _, info := range authInfo {
		fmt.Println(info)
		if len(info.Issuer) == 0 || len(info.AppName) == 0 ||
			len(info.NetworkCard) == 0 || len(info.Ip) == 0 || len(info.Mac) == 0 || len(info.CustomerInfo) == 0 {
			fmt.Println("参数，Issuer，AppName，NetworkCard，Ip，Mac，CustomerInfo不能为空")
			responseInfo.ErrorInfo = append(responseInfo.ErrorInfo, "参数，Issuer，AppName，NetworkCard，Ip，Mac，CustomerInfo不能为空")
			continue
		}
		if certPath, err := NewCertificateInfoByPrivateBytes(info, []byte(PrivateKey)); err != nil {
			responseInfo.ErrorInfo = append(responseInfo.ErrorInfo, "appName: "+info.AppName+" Ip: "+info.Ip+",error: "+err.Error())
			fmt.Println("NewCertificateInfoByPrivate error: ", err)
		} else {
			responseInfo.DownloadCertPath = append(responseInfo.DownloadCertPath, certPath)
		}
	}

	responseBytes, err := json.Marshal(responseInfo)
	if err != nil {
		fmt.Println("serialized json error")
	}

	if _, err := rw.Write(responseBytes); err != nil {
		fmt.Println("write response info error:", err.Error())
	}
}

func (ri *AuthorizationInfo) SetStart(start int64) {
	ri.NotBefore = start
}

func (ri *AuthorizationInfo) SetStop(stop int64) {
	ri.NotAfter = stop
}
func (ri *AuthorizationInfo) GetStart() int64 {
	return ri.NotBefore
}
func (ri *AuthorizationInfo) GetStop() int64 {
	return ri.NotAfter
}

type CertificateInfo struct {
	License   string  `json:"license"` //激活码
	Signature []uint8 `json:"signature"`
}

// NewCertificateInfo 根据传入的AuthorizationInfo 生成证书信息，没有指定私钥会自动生成私钥
func NewCertificateInfo(authInfo *AuthorizationInfo) error {
	//生成对成加密key
	aesKey, err := aes_util.GenerateRandomCode(16)
	if err != nil {
		return errors.New("generate error," + err.Error())
	}
	//对数据进行对成加密
	authInfoBytes, err := json.Marshal(authInfo)
	if err != nil {
		return err
	}
	authAesEncryptData, err := aes_util.EncryptAes(authInfoBytes, aesKey)
	//对成加密后的数据长度
	aesEncLength := len(authAesEncryptData)
	//生成非对称密钥
	rsa_util.GetKeys(LicenseCache + "/" + aesKey)
	//私钥签名
	rsaSign, err := rsa_util.RsaSignWithSha256ByFile([]byte(authAesEncryptData), LicenseCache+"/"+aesKey+"_private.pem")

	licenseStr := aesKey + strconv.Itoa(aesEncLength) + "_" + authAesEncryptData

	//生成证书文件
	fp, _ := os.Create(LicenseCache + "/" + aesKey + "_certificate.json")
	defer fp.Close()
	certificateInfo := &CertificateInfo{
		License:   licenseStr,
		Signature: rsaSign,
	}
	certByts, err := json.Marshal(certificateInfo)
	if err != nil {
		return err
	}

	_, err = fp.Write(certByts)
	if err != nil {
		return err
	}

	return nil
}

// NewCertificateInfoByPrivateFile 根据传入的AuthorizationInfo 以及私钥生成证书信息
func NewCertificateInfoByPrivateFile(authInfo *AuthorizationInfo, rsaPrivateKeyPath string) error {

	authInfo.SetStart(time.Now().Unix())
	authInfo.SetStop(time.Now().Unix() + int64(3600*24*authInfo.Duration))

	//生成对成加密key
	aesKey, err := aes_util.GenerateRandomCode(16)
	if err != nil {
		return errors.New("generate error," + err.Error())
	}
	//对数据进行对成加密
	authInfoBytes, err := json.Marshal(authInfo)
	if err != nil {
		return errors.New("marshal error," + err.Error())
	}
	authAesEncryptData, err := aes_util.EncryptAes(authInfoBytes, aesKey)
	//对成加密后的数据长度
	aesEncLength := len(authAesEncryptData)
	//私钥签名
	rsaSign, err := rsa_util.RsaSignWithSha256ByFile([]byte(authAesEncryptData), rsaPrivateKeyPath)

	licenseStr := aesKey + strconv.Itoa(aesEncLength) + "_" + authAesEncryptData

	//生成证书文件
	fp, _ := os.Create(LicenseCache + "/" + authInfo.AppName + "_" + authInfo.Ip + "_certificate.json")
	defer fp.Close()
	certificateInfo := &CertificateInfo{
		License:   licenseStr,
		Signature: rsaSign,
	}
	certByts, err := json.Marshal(certificateInfo)
	if err != nil {
		return errors.New("marshal error," + err.Error())
	}

	_, err = fp.Write(certByts)
	if err != nil {
		return errors.New("write file error:" + err.Error())
	}

	return nil
}

// NewCertificateInfoByPrivateBytes 根据传入的AuthorizationInfo 以及私钥生成证书信息
func NewCertificateInfoByPrivateBytes(authInfo *AuthorizationInfo, rsaPrivateKeyBytes []byte) (string, error) {
	authInfo.SetStart(time.Now().Unix())
	authInfo.SetStop(time.Now().Unix() + int64(3600*24*authInfo.Duration))

	//生成对成加密key
	aesKey, err := aes_util.GenerateRandomCode(16)
	if err != nil {
		return "", errors.New("generate key error," + err.Error())
	}
	//对数据进行对成加密
	authInfoBytes, err := json.Marshal(authInfo)
	if err != nil {
		return "", errors.New("marshal error," + err.Error())
	}
	authAesEncryptData, err := aes_util.EncryptAes(authInfoBytes, aesKey)
	if err != nil {
		return "", errors.New("encrypt failure, error info:" + err.Error())
	}
	//对成加密后的数据长度
	aesEncLength := len(authAesEncryptData)
	//私钥签名
	rsaSign, err := rsa_util.RsaSignWithSha256ByBytes([]byte(authAesEncryptData), rsaPrivateKeyBytes)

	licenseStr := aesKey + strconv.Itoa(aesEncLength) + "_" + authAesEncryptData

	//生成证书文件
	fp, _ := os.Create(LicenseCache + "/" + authInfo.AppName + "_" + authInfo.Ip + "_certificate.json")
	defer fp.Close()
	certificateInfo := &CertificateInfo{
		License:   licenseStr,
		Signature: rsaSign,
	}
	certByts, err := json.Marshal(certificateInfo)
	if err != nil {
		return "", errors.New("marshal certificate error," + err.Error())
	}
	_, err = fp.Write(certByts)
	if err != nil {
		return "", errors.New("write certificate error," + err.Error())
	}
	return authInfo.AppName + "_" + authInfo.Ip + "_certificate.json", nil
}

// ParseCertificateByPublicKeyFile 根据公钥路径读出证书，验证签发的证书是否有效
func ParseCertificateByPublicKeyFile(cert *CertificateInfo, rsaPubKeyPath string) (*AuthorizationInfo, error) {
	//拆解license
	certDataStr, signatureInfo, aesKey := parseCertificate(cert)
	if certDataStr == nil || signatureInfo == nil || len(aesKey) == 0 {
		return nil, errors.New("certificate verification failure")
	}
	//验证签名
	bSuccess, err := rsa_util.RsaVisaSignWithSha256ByFile(certDataStr, signatureInfo, rsaPubKeyPath)
	if !bSuccess {
		return nil, errors.New("rsa very")
	}
	//对成数据解密
	authStr, err := aes_util.DecryptAes(string(certDataStr), aesKey)
	if err != nil {
		return nil, errors.New("decryption failure, error info:" + err.Error())
	}
	authInfo := &AuthorizationInfo{}
	if err = json.Unmarshal([]byte(authStr), authInfo); err != nil {
		return nil, errors.New("unmarshal failure, error info:" + err.Error())
	}

	return authInfo, nil
}

// ParseCertificateByPublicKeyBytes 根据公钥字节流验证签发的证书是否有效
func ParseCertificateByPublicKeyBytes(cert *CertificateInfo, publicKeyBytes []byte) (*AuthorizationInfo, error) {
	//拆解license
	certDataStr, signatureInfo, aesKey := parseCertificate(cert)
	if certDataStr == nil || signatureInfo == nil || len(aesKey) == 0 {
		return nil, errors.New("certificate verification failure")
	}
	//验证签名
	bSuccess, err := rsa_util.RsaVisaSignWithSha256ByByBytes(certDataStr, signatureInfo, publicKeyBytes)

	if !bSuccess {
		return nil, errors.New("rsa visa sign failure, error info:" + err.Error())
	}
	//对成数据解密
	authStr, err := aes_util.DecryptAes(string(certDataStr), aesKey)
	if err != nil {
		return nil, errors.New("decrypt failure, error info:" + err.Error())
	}
	authInfo := &AuthorizationInfo{}
	if err = json.Unmarshal([]byte(authStr), authInfo); err != nil {
		return nil, errors.New("certificate verification failure")
	}
	return authInfo, nil
}

func parseCertificate(cert *CertificateInfo) ([]byte, []uint8, string) {
	if len(cert.License) == 0 {
		fmt.Println("certificate verification failure, license is empty")
		return nil, nil, ""
	}
	aesKey := cert.License[:16]
	fmt.Println(aesKey)

	makeIndex := strings.Index(cert.License, "_")
	if makeIndex == -1 {
		fmt.Println("certificate verification failure, makeIndex is -1")
		return nil, nil, aesKey
	}
	dateLength, err := strconv.Atoi(cert.License[16:makeIndex])
	if err != nil {
		fmt.Println("certificate verification failure, error info:", err.Error())
		return nil, nil, aesKey
	}
	dataEndIndex := makeIndex + dateLength + 1
	//对称加密数据
	certDataStr := cert.License[makeIndex+1 : dataEndIndex]
	//签名
	signatureInfo := cert.Signature

	return []byte(certDataStr), signatureInfo, aesKey
}

// CheckLicenseByPublicKeyFile 读取签证内容，进行签证校验，publicKey 为公钥文件路径
func CheckLicenseByPublicKeyFile(certificatePath, aesPublicKey string) (*AuthorizationInfo, error) {
	//从文件读出签证信息
	fp, err := os.Open(certificatePath)
	defer fp.Close()

	if err != nil {
		return nil, errors.New("open certificate file error " + err.Error())
	}
	decord := json.NewDecoder(fp)
	certInfo := &CertificateInfo{}
	err = decord.Decode(certInfo)
	if err != nil {
		return nil, errors.New("decode certificate file error " + err.Error())
	}

	//解析签证
	authInfo, err := ParseCertificateByPublicKeyFile(certInfo, aesPublicKey)
	return authInfo, err
}

// CheckLicenseByPublicKeyBytes 读取签证内容，进行签证校验,publicKey 为字节流公钥
func CheckLicenseByPublicKeyBytes(certificatePath string, publicKeyBytes []byte) (*AuthorizationInfo, error) {
	//从文件读出签证信息
	fp, err := os.Open(certificatePath)
	defer fp.Close()
	if err != nil {
		return nil, errors.New("open certificate file error " + err.Error())
	}
	decord := json.NewDecoder(fp)
	certInfo := &CertificateInfo{}
	err = decord.Decode(certInfo)
	if err != nil {
		return nil, errors.New("decode certificate file error " + err.Error())
	}

	//解析签证
	authInfo, err := ParseCertificateByPublicKeyBytes(certInfo, publicKeyBytes)
	return authInfo, err
}
