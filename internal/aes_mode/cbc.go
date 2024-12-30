package aesMode

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"github.com/dhlanshan/wind/internal/utils"
)

type CBC struct{}

// Encrypt 密码分组链接模式
func (cbc *CBC) Encrypt(plainText, key, iv, nonce, additionalData []byte, paddingType int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("iv length must equal block size. AES is fixed at 128 bits")
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// 补码
	if plainText, err = utils.Padding(plainText, blockSize, paddingType); err != nil {
		return nil, err
	}
	cipherText := make([]byte, len(plainText))
	blockMode.CryptBlocks(cipherText, plainText)

	return cipherText, nil
}

// Decrypt 密码分组链接模式
func (cbc *CBC) Decrypt(cipherText, key, iv, nonce, additionalData []byte, paddingType int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(iv) != blockSize {
		return nil, errors.New("iv length must equal block size. AES is fixed at 128 bits")
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(plainText, cipherText)
	// 解码
	if plainText, err = utils.UnPadding(plainText, paddingType); err != nil {
		return nil, err
	}

	return plainText, nil
}
