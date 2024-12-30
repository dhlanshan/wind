package utils

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
)

// Padding 填充数据
func Padding(data []byte, blockSize int, paddingType int) ([]byte, error) {
	pMap := map[int]func([]byte, int) ([]byte, error){
		1: noPadding,
		2: pkcs5Padding,
		3: pkcs7Padding,
		4: iso10126Padding,
		5: zeroPadding,
		6: anisX923Padding,
	}
	pFun, ok := pMap[paddingType]
	if !ok {
		return nil, errors.New("填充类型不存在")
	}

	return pFun(data, blockSize)
}

// UnPadding 去除填充
func UnPadding(data []byte, paddingType int) ([]byte, error) {
	uMap := map[int]func([]byte) ([]byte, error){
		1: noUnPadding,
		2: pkcs5UnPadding,
		3: pkcs7UnPadding,
		4: iso10126UnPadding,
		5: zeroUnPadding,
		6: anisX923UnPadding,
	}
	uFun, ok := uMap[paddingType]
	if !ok {
		return nil, errors.New("填充类型不存在")
	}

	return uFun(data)
}

// noPadding 无填充
func noPadding(data []byte, blockSize int) ([]byte, error) {
	if len(data)%blockSize != 0 {
		return nil, errors.New("内容长度不是块的整数倍")
	}
	return data, nil
}

func noUnPadding(data []byte) ([]byte, error) {
	return data, nil
}

// pkcs5Padding PKCS5填充
func pkcs5Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize != 8 {
		return nil, errors.New(fmt.Sprintf("PKCS5Padding块大小固定为8bytes. 当前块大小为: %dbytes", blockSize))
	}

	return pkcs7Padding(data, blockSize)
}

// pkcs5UnPadding PKCS5去除填充
func pkcs5UnPadding(data []byte) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	upd := int(data[dataLength-1])
	if upd > 8 || upd < 1 {
		return nil, errors.New(fmt.Sprintf("PKCS5Padding填充字节范围为1~8bytes, 当前填充字节为:%d", upd))
	}

	return data[:(dataLength - upd)], nil
}

// pkcs7Padding PKCS7填充
func pkcs7Padding(data []byte, blockSize int) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	if blockSize > 256 || blockSize < 1 {
		return nil, errors.New(fmt.Sprintf("PKCS7Padding块大小为1~256bytes. 当前块大小为: %dbytes", blockSize))
	}
	pd := blockSize - dataLength%blockSize
	padText := bytes.Repeat([]byte{byte(pd)}, pd)

	return append(data, padText...), nil
}

// pkcs7UnPadding PKCS7去除填充
func pkcs7UnPadding(data []byte) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	upd := int(data[dataLength-1])
	if upd > 256 || upd < 1 {
		return nil, errors.New(fmt.Sprintf("PKCS7Padding填充字节范围为1~256bytes, 当前填充字节为:%d", upd))
	}

	return data[:(dataLength - upd)], nil
}

// zeroPadding Zero填充
func zeroPadding(data []byte, blockSize int) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	pd := blockSize - dataLength%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, pd)

	return append(data, padText...), nil
}

// zeroUnPadding Zero取消填充
func zeroUnPadding(data []byte) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	for i := dataLength - 1; i > 0; i-- {
		if pd := data[i]; pd != 0 {
			return data[:i+1], nil
		}
	}

	return []byte{}, nil
}

// iso10126Padding ISO10126填充
func iso10126Padding(data []byte, blockSize int) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	pd := blockSize - dataLength%blockSize
	// 生成padding-1个随机字符
	padText := make([]byte, pd-1)
	_, _ = rand.Read(padText)
	// 最后位加上padding字符
	padText = append(padText, byte(pd))

	return append(data, padText...), nil
}

// iso10126UnPadding ISO10126取消填充
func iso10126UnPadding(data []byte) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	upd := int(data[dataLength-1])
	if upd > dataLength {
		return nil, errors.New("填充位数超过数据长度")
	}

	return data[:(dataLength - upd)], nil
}

// anisX923Padding ANISx923填充
func anisX923Padding(data []byte, blockSize int) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	pd := blockSize - dataLength%blockSize
	padText := bytes.Repeat([]byte{byte(0)}, pd-1)
	// 最后位加上padding字符
	padText = append(padText, byte(pd))

	return append(data, padText...), nil
}

// anisX923UnPadding ANISx923取消填充
func anisX923UnPadding(data []byte) ([]byte, error) {
	dataLength := len(data)
	if dataLength == 0 {
		return nil, errors.New("数据为空")
	}
	upd := int(data[dataLength-1])
	if upd > dataLength {
		return nil, errors.New("填充位数超过数据长度")
	}

	return data[:(dataLength - upd)], nil
}
