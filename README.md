# blicense

此项目用于生成 license；

目的：限制私有化部署应用的权限问题

鉴权属性
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
}
生成证书需要配置的信息，或者说是证书中会携带的内容；如 AuthorizationInfo 的属性所示；


**licese**,的生成原理参考如下链接：
https://zhuanlan.zhihu.com/p/187585495
