package aesMode

import (
	"crypto/aes"
	"github.com/dhlanshan/wind/internal/util"
)

type ECB struct{}

// Encrypt 电子密码本模式
func (ecb *ECB) Encrypt(plainText, key, iv []byte, paddingType int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	// 补码
	if plainText, err = util.Padding(plainText, blockSize, paddingType); err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(plainText))
	// 对每个数据块独立进行加密
	for i := 0; i < len(plainText); i += aes.BlockSize {
		block.Encrypt(cipherText[i:i+aes.BlockSize], plainText[i:i+aes.BlockSize])
	}

	return cipherText, nil
}

// Decrypt d
func (ecb *ECB) Decrypt(cipherText, key, iv []byte, paddingType int) ([]byte, error) {
	// 块
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(cipherText))
	// 对每个数据块独立进行解密
	for i := 0; i < len(cipherText); i += aes.BlockSize {
		block.Decrypt(plainText[i:i+aes.BlockSize], cipherText[i:i+aes.BlockSize])
	}

	// 解码
	if plainText, err = util.UnPadding(plainText, paddingType); err != nil {
		return nil, err
	}

	return plainText, nil
}
