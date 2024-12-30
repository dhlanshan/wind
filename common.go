package wind

import (
	aesMode "github.com/dhlanshan/wind/internal/aes_mode"
	"sync"
)

type AesMode func(plainText, key, iv []byte, paddingType int) ([]byte, error)

type AbstractMode interface {
	Encrypt(plainText, key, iv, nonce, additionalData []byte, paddingType int) ([]byte, error)
	Decrypt(cipherText, key, iv, nonce, additionalData []byte, paddingType int) ([]byte, error)
}

var modeMap sync.Map
var modeNameList []string
var modeList = map[string]AbstractMode{"CBC": &aesMode.CBC{}, "ECB": &aesMode.ECB{}, "GCM": &aesMode.GCM{}}

func init() {
	for k, v := range modeList {
		modeMap.Store(k, v)
		modeNameList = append(modeNameList, k)
	}
}
