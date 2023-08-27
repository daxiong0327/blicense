package blicense

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const issuer = "daxiong"

// CheckLicenseValidity 检查证书有效性,验证公钥的实际内容
func CheckLicenseValidity(certificatePath, publicKey string) (bool, error) {
	authInfo, err := CheckLicenseByPublicKeyBytes(certificatePath, []byte(publicKey))
	if err != nil {
		return false, errors.New("check license validity failure, error info is:" + certificatePath + "\nerror info is:" + err.Error())
	}
	//验证签发人
	if authInfo.Issuer != "issuer" {
		return false, errors.New("certificate verification failure. Not issued by issuer")
	}

	//验证网卡信息
	bNetwork, err := checkNetworkCard(authInfo)
	if !bNetwork {
		return false, errors.New("network card or ip verification failure, error info is:" + err.Error())
	}
	//验证时间信息
	currentTime := time.Now().Unix()
	if currentTime < authInfo.GetStart() || currentTime > authInfo.GetStop() {
		return false, errors.New("certificate has expired")
	}
	return true, nil
}

// checkNetworkCard 检查网卡信息
func checkNetworkCard(authInfo *AuthorizationInfo) (bool, error) {

	networkInfo, err := net.Interfaces()
	if err != nil {
		return false, err
	}

	var bNetwork bool
	for _, info := range networkInfo {
		//fmt.Println("Network card name:", info.Name)
		if info.Name != authInfo.NetworkCard {
			continue
		}
		s := ""
		for i, b := range info.HardwareAddr {
			if i != 0 {
				s += ":"
			}
			s += fmt.Sprintf("%02x", b)
		}
		if strings.ToUpper(s) != strings.ToUpper(authInfo.Mac) { //nolint:staticcheck
			fmt.Println("find mac address failure")
			continue
		}
		byNameInterface, err := net.InterfaceByName(info.Name)
		if err != nil {
			fmt.Println("get network card info failure")
			continue
		}
		address, err := byNameInterface.Addrs()
		if err != nil {
			fmt.Println("analysis network card address failure")
			continue
		}
		for _, value := range address {
			if ipNet, ok := value.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ipNet.IP.To4() != nil && ipNet.IP.String() != authInfo.Ip {
					continue
				}
				bNetwork = true
				break
			}
		}
		if bNetwork {
			break
		}
	}
	return bNetwork, nil
}