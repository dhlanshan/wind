package wind

import (
	"errors"
	"github.com/dhlanshan/wind/internal/tools"
	"github.com/dhlanshan/wind/internal/utils"
)

type Aes struct {
	Mode           string
	Key            string
	Iv             string
	Nonce          string
	Padding        PaddingEnum
	AdditionalData string
}

func (a *Aes) AddMode(modeName string, mode AbstractMode) error {
	if tools.InSlice(modeNameList, modeName) {
		return errors.New("unable to modify the default mode")
	}
	modeMap.Store(modeName, mode)

	return nil
}

func (a *Aes) Encrypt(plainText []byte, format FormatEnum) (ciphertext string, err error) {
	if plainText == nil || len(plainText) == 0 {
		return "", errors.New("empty plain text")
	}

	v, ok := modeMap.Load(a.Mode)
	if !ok {
		return "", errors.New("mode not exist")
	}
	mode := v.(AbstractMode)
	cipherByte, err := mode.Encrypt(plainText, []byte(a.Key), []byte(a.Iv), []byte(a.Nonce), []byte(a.AdditionalData), int(a.Padding))
	if err != nil {
		return "", err
	}

	ciphertext = utils.PackDataToStr(cipherByte, string(format))
	return
}

func (a *Aes) Decrypt(cipherText string, format FormatEnum) (plainByte []byte, err error) {
	if cipherText == "" {
		return nil, errors.New("empty cipherText")
	}
	cipherByte, err := utils.PackDataToByte(cipherText, string(format))
	if err != nil {
		return nil, err
	}

	v, ok := modeMap.Load(a.Mode)
	if !ok {
		return nil, errors.New("mode not exist")
	}
	mode := v.(AbstractMode)
	plainByte, err = mode.Decrypt(cipherByte, []byte(a.Key), []byte(a.Iv), []byte(a.Nonce), []byte(a.AdditionalData), int(a.Padding))

	return
}
