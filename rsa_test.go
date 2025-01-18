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

func TestLoadCertByRaw(t *testing.T) {
	rsa := Rsa{}
	_ = rsa.LoadCertByRaw("MIIEtTCCAp2gAwIBAgIUDyuccmylba71lZQAQic5TJiAhwwwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAwwNSmV0UHJvZmlsZSBDQTAeFw0yMzA5MjkxNDA2MTJaFw0zMzA5MjcxNDA2MTJaMBExDzANBgNVBAMMBk5vdmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALenqcGP2ZxGkYqmKA9c4Hzf8+YD1smvmOxKjd+bmTLrutM/hXv1cj1rW3/lqyDtdDk7K6W8/TDq1CRrEt+Do6l30DxhAiC34aH8DmGwgq77xEoLimvH5LpePxflF+tbB1RZtFgFDOIYLdSQaKFH2JDgVKxhLiV3S6jniPhkCtWWrTs+E6vq4N15Bm3NnM5AJILqjtUbOjNfaxVq6RrOoTc0R3Fqqo6yvxo/+JYa2UnHIC+r2dbKuDLMUrtgnydEUdJNX0zH9FtcdELvr48uc9mY038TWUsZUK1pnQbxA2bPyA4qnYJ9IvUgO6LtLXvGFm137YQMS1N41AHDBOrwoNI8UoDX+qI3rM96biFOFvn7Edky7rByzybt3H+zxdojfjvpL1E0NO98BT9zfufHAaAxZtlmDOu5LDJe3CGurnyRMRExbtc+Qjl1mUh6tG4lakAwdsoxry0GdG72yaYyb9it53kaFks/T/s7Z7bRJzVFzQDV1Y4bzUtk43vKm2vztBVlQkBkZY5f2Jbe5Ig3b8swQzBnOT0mrL5SPUhwmQ6IxkEWztj55OEujBMmRr92oESuq9ZYMaeLidKWVR3/++HA8BRZaRGEKtSHZCbFEFdihDxxJv9Xh6NuT/ewJ6HYp+0NQpFnUnJ72n8wV+tudpam7aKcdzVmz7cNwOhG2Ls7AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAIdeaQfKni7tXtcywC3zJvGzaaj242pSWB1y40HW8jub0uHjTLsBPX27iA/5rb+rNXtUWX/f2K+DU4IgaIiiHhkDrMsw7pivazqwA9h7/uA0A5nepmTYf/HY4W6P2stbeqInNsFRZXS7Jg4Q5LgEtHKo/H8USjtVw9apmE3BCElkXRuelXMsSllpR/JEVv/8NPLmnHSY02q4KMVW2ozXtaAxSYQmZswyP1YnBcnRukoI4igobpcKQXwGoQCIUlec8LbFXYM9V2eNCwgABqd4r67m7QJq31Y/1TJysQdMH+hoPFy9rqNCxSq3ptpuzcYAk6qVf58PrrYH/6bHwiYPAayvvdzNPOhM9OCwomfcazhK3y7HyS8aBLntTQYFf7vYzZxPMDybYTvJM+ClCNnVD7Q9fttIJ6eMXFsXb8YK1uGNjQW8Y4WHk1MCHuD9ZumWu/CtAhBn6tllTQWwNMaPOQvKf1kr1Kt5etrONY+B6O+Oi75SZbDuGz7PIF9nMPy4WB/8XgKdVFtKJ7/zLIPHgY8IKgbx/VTz6uBhYo8wOf3xzzweMnn06UcfV3JGNvtMuV4vlkZNNxXeifsgzHugCvJX0nybhfBhfIqVyfK6t0eKJqrvp54XFEtJGR+lf3pBfTdcOI6QFEPKGZKoQz8Ck+BC/WBDtbjc/uYKczZ8DKZu", Base64)
	fmt.Println(rsa.GetCertStr())
}
