# blicense
### 目的
用于生成 license，并做授权验证。私有化部署应用或服务，时常需要做授权验证，以保证应用或服务的正常运行。保证个人或公司的知识产权。

鉴权属性
```go
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
```

生成证书需要配置的信息，或者说是证书中会携带的内容；如 AuthorizationInfo 的属性所示；
可根据自身的业务需要对 AuthorizationInfo 进行扩展，如增加授权的功能点，或者增加授权的数量等等。

### 加密原理
- 对称加密使用aes算法，用于对授权信息进行加密；
- 非堆成加密使用rsa算法，用于生成签名信息，用于验证授权证书的合法性；


**licese**,的生成原理参考如下链接：
https://zhuanlan.zhihu.com/p/187585495
