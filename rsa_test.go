package wind

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"testing"
	"time"
)

func TestGenerateKey(t *testing.T) {
	rsa := Rsa{}
	err := rsa.GenerateKey(RSA4096)
	fmt.Println(err)
}

func TestGetKey(t *testing.T) {
	rsa := Rsa{}
	_ = rsa.GenerateKey(RSA4096)
	pri, pub, err := rsa.GetKeyStr(PKCS8)
	fmt.Println(pri)
	fmt.Println(pub)
	fmt.Println(err)
}

func TestSaveKey(t *testing.T) {
	rsa := Rsa{}
	_ = rsa.GenerateKey(RSA4096)
	err := rsa.SaveKey(PKCS1, "", "")
	fmt.Println(err)
}

func TestLoadKeyByFile(t *testing.T) {
	rsa := Rsa{}
	err := rsa.LoadKeyByFile("./wind_private_key.pem")
	fmt.Println(err)
	pri, pub, err := rsa.GetKeyStr(PKCS1)
	fmt.Println(pri)
	fmt.Println(pub)
	fmt.Println(err)
}

func TestBuildCertAndSave(t *testing.T) {
	fatherRsa := Rsa{}
	_ = fatherRsa.GenerateKey(RSA4096)
	rsa := Rsa{}
	err := rsa.LoadKeyByFile("./wind_private_key.pem")
	fmt.Println(err)
	template := &x509.Certificate{
		SerialNumber: rsa.GenSerialNumber(),
		Subject: pkix.Name{
			CommonName: "我是子证书的名字", // 固定名称,不可修改
		},
		Issuer: pkix.Name{
			CommonName: "我是父证书的名字", // 固定名称,不可修改
		},
		NotBefore:          time.Now().AddDate(0, 0, -1),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          rsa.GetPublic(),
	}
	patter := &x509.Certificate{
		SerialNumber: rsa.GenSerialNumber(),
		Subject: pkix.Name{
			CommonName: "我是父证书的名字", // 固定名称,不可修改
		},
		NotBefore:          time.Now().AddDate(0, 0, -1),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		PublicKeyAlgorithm: x509.RSA,
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKey:          fatherRsa.GetPublic(),
	}
	err = rsa.BuildCert(template, patter, fatherRsa.GetPrivate())
	fmt.Println(err)
	err = rsa.SaveCert("", "ccc")
	fmt.Println(err)
}

func TestLoadCertByFile(t *testing.T) {
	rsa := Rsa{}
	err := rsa.LoadCertByFile("./wind_cert.pem")
	ss, err := rsa.GetCertStr()
	fmt.Println(ss)
	fmt.Println(err)
}

func TestSign(t *testing.T) {
	rsa := Rsa{}
	err := rsa.LoadKeyByFile("./wind_private_key.pem")
	fmt.Println(err)
	msg := "飞流直下三千尺, 疑是银河落九天"
	cipText, err := rsa.Sign([]byte(msg), PSS, Sha256, Base64RawUrl, nil)
	fmt.Println(cipText)
	fmt.Println(err)
}

func TestVerify(t *testing.T) {
	rsa := Rsa{}
	err := rsa.LoadKeyByFile("./wind_private_key.pem")
	fmt.Println(err)
	msg := "飞流直下三千尺, 疑是银河落九天"
	c := "QzH0rFItrY5Mt-LsCV5CgXo6NM09XmEbfKIO7ZeITo4k1EKMEwvhMyVU8CJQeeMxb5XBt5Gxy_3vmPkEX5WxEzC8UaMucAPPqHhMZMLtO69Pn9WLw2qxOCTUHXZ0z4imfw6dOq7IKyrYKHzckEoYd4L79J7fB7_N_3B4GBRIdKf7b1tbxvftt0hO_DCHicO9bT7PM-cj10qVeMavkGPpJWZZ4hHFjJZx-UJ5KdpKr8ZR-b7k_eTSWrvuEVz7IFVPGTw0ihDEryn1RVvyxYfyfBJojsGx8YAgwmwK_ppypiFBnprTJLaAj6JyDsaBm72ImzExSzsEtTrUDc59N_bsqAsMIC0ZTnhfdwxIkCbAA-5VmtKa_v0oD9cgTVg3p9D74NuWJdbUqt9pOt0i1YIoq2zWUOSpXHvNgo3GRgXPKEj2Wpd-FC7irGljG6cQ9dzGK0ru6GdLnLt20x6y-wJvwOZbBpNaazZW-b5XWxl8hGIXM-MJGJbTUUbuop_AJiWx9TUhCJ1uNrKSwcUWoPfeB85-8Axxn8GkCxg7wZbrYDlFujkd_O9NPSxOJaQayfN-gLelWr_BRcM4rNdyG84MQRMoat-xhTHFotr0O4p8i_5HU4i09-rU5_btod_7SbVVWXlo5WDYlH23ZMwk9spJc6w_L2siXRK6PWpMvprVwgQ"
	err = rsa.VerifySign([]byte(msg), c, PSS, Sha256, Base64RawUrl, nil)
	fmt.Println(err)
}

func TestEncrypt(t *testing.T) {
	rsa := Rsa{}
	err := rsa.LoadKeyByFile("./wind_private_key.pem")
	msg := "飞流直下三千尺, 疑是银河落九天"
	cipText, err := rsa.Encrypt([]byte(msg), OAEPPadding, Sha256, Base64, []byte("zzzzjjjkkk"))
	fmt.Println(cipText)
	fmt.Println(err)
}

func TestDecrypt(t *testing.T) {
	rsa := Rsa{}
	err := rsa.LoadKeyByFile("./wind_private_key.pem")
	msg := "O8ZfnYNIjf+wtHiRPz/ZFqtb5cTJWR2wPSoAxPnWGNLXIsCOQTrs4nfRrnNftnwoyP4yD8DYHLQxJrfo0fHa5+IkF2y8jis8CClY0yktSOI8nvttqW6KROZdeJQlOi5YRcqW3wd0ycukDa4R8wEihG7BI8qL92UQ0pXXfjv1koHHq7CYjuSY2TrI1XMqcfmaz7pBNEDirMUiv259e2kRyAx/LQ7E7gefEzxikhTN2ptMyUJL48e2gp6VW8K9pUlMg7NRkbQptdpfwiDeuOLOw52Txm2YazD3osf4J6qMUFLUFYgunbXeWJ7QGmV9d+SCq4zcLPIWhwaeH391u+9OleJrE0wXOBHF+7sUKKvM2p4kQrmdDazdV5tblF2lZU8t6GjrDmlEtZYxX+JxFM5TjaI2G8C9iGYR2/kkU5hazhlCh+f1IYuQnEh2kgrM69b/1/YEnJLvle1eOoXDj6wf7ZYufQ8RBSxWGwsicqMNh+ZEkaduoqjWZ8O5xiPXw83pMCXzpVOk8nwqSJnMlgAaJwBmqZQ7gUJxVnWbiKdN3EGob6drSbSUlEonEhycqMz7PfLO4TrxN4cNbYMxBluXhGzxb87W5vn5lPlVci9AiYcF3w4onZdXV7KXSFyTBGAB7HC7Ya9DHbeBrhZUNcb1JGWxF/w4yT7CjY2tCMBXUGk="
	pText, err := rsa.Decrypt(msg, OAEPPadding, Sha256, Base64, []byte("zzzzjjjkkk"))
	fmt.Println(string(pText))
	fmt.Println(err)
}
