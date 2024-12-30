package utils

import (
	"encoding/base64"
	"encoding/hex"
)

func PackDataToStr(content []byte, format string) string {
	switch format {
	case "hex":
		return hex.EncodeToString(content)
	case "base64":
		return base64.StdEncoding.EncodeToString(content)
	case "base64url":
		return base64.URLEncoding.EncodeToString(content)
	case "base64rawUrl":
		return base64.RawURLEncoding.EncodeToString(content)
	default:
		return string(content)
	}

}

func PackDataToByte(content string, format string) (data []byte, err error) {
	switch format {
	case "hex":
		return hex.DecodeString(content)
	case "base64":
		return base64.StdEncoding.DecodeString(content)
	case "base64url":
		return base64.URLEncoding.DecodeString(content)
	case "base64rawUrl":
		return base64.RawURLEncoding.DecodeString(content)
	default:
		return []byte(content), nil
	}
}
