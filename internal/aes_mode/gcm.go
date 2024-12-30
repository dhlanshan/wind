package aesMode

import (
	"crypto/aes"
	"crypto/cipher"
)

type GCM struct{}

func (gcm *GCM) Encrypt(plainText, key, iv, nonce, additionalData []byte, paddingType int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	cipherText := aesGCM.Seal(nil, nonce, plainText, additionalData)
	return cipherText, nil
}

func (gcm *GCM) Decrypt(cipherText, key, iv, nonce, additionalData []byte, paddingType int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plainText, err := aesGCM.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
