package wind

import (
	"fmt"
	"testing"
)

func TestCBCEncrypt(t *testing.T) {
	aes := &Aes{Mode: "CBC", Key: "zjkjhuhuhsjhuhjq", Iv: "qowieurjfhturjfh", Padding: PKCS7}
	msg := `飞流直是九天飞银河落九天飞流直下三千尺, 疑是银河落九天飞流直下三千尺, 疑是是银河落九天`
	cc, err := aes.Encrypt([]byte(msg), Base64)
	fmt.Println(cc)
	fmt.Println(err)
}

func TestCBCDecrypt(t *testing.T) {
	aes := &Aes{Mode: "CBC", Key: "zjkjhuhuhsjhuhjq", Iv: "qowieurjfhturjfh", Padding: PKCS7}
	msg := "Tx9solShY4ZfB0Se+87rXI9ToDv9zfeROqovB3Pwdok1lMDG6LmtsAt4+fbU5F0NOV0jUKqqRqtENjJkRicjPYk0fV6lp3NXiirU0fcuy9YVQlM01QOOCcQYr2OgdzbAgTfhGbqKY5lEy9Ym6Fx2S1vbj2HisQq2fP/SM4Ws4nA="
	cc, err := aes.Decrypt(msg, Base64)
	fmt.Println(string(cc))
	fmt.Println(err)
}

func TestECBEncrypt(t *testing.T) {
	aes := &Aes{Mode: "ECB", Key: "zjkjhuhuhsjhuhjq", Iv: "qowieurjfhturjfh", Padding: PKCS7}
	msg := `飞流直是九天飞银河落九天飞流直下三千尺, 疑是银河落九天飞流直下三千尺, 疑是是银河落九天`
	cc, err := aes.Encrypt([]byte(msg), Base64)
	fmt.Println(cc)
	fmt.Println(err)
}

func TestECBDecrypt(t *testing.T) {
	aes := &Aes{Mode: "ECB", Key: "zjkjhuhuhsjhuhjq", Iv: "qowieurjfhturjfh", Padding: PKCS7}
	msg := "MKXRMGEa/7EoaYCVvChmtd36vL6XwsR0Zkj5X7NRJ0JsbGO9O2CT5qfPs+jb8rshkzFW5YUxT73q5w111l6sdR1C6HA9JS1bydGVvqliFuhkPqu/hYa2C26E7XFWLxHgZXlWbo+j8ti/BaLpnuMEjDotJSljSAnSyauh3d7trow="
	cc, err := aes.Decrypt(msg, Base64)
	fmt.Println(string(cc))
	fmt.Println(err)
}
