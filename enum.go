package wind

type SignTypeEnum string

const (
	PKCS1v15 SignTypeEnum = "PKCS1v15"
	PSS      SignTypeEnum = "PSS"
)

type CryptoPaddingEnum string

const (
	PKCS1v15Padding CryptoPaddingEnum = "PKCS1v15"
	OAEPPadding     CryptoPaddingEnum = "OAEP"
)

type HashTypeEnum string

const (
	Sha1   HashTypeEnum = "SHA1"
	Sha224 HashTypeEnum = "SHA224"
	Sha256 HashTypeEnum = "SHA256"
	Sha384 HashTypeEnum = "SHA384"
	Sha512 HashTypeEnum = "SHA512"
)

type RsaKeySizeEnum int

const (
	RSA2048 RsaKeySizeEnum = 2048
	RSA3072 RsaKeySizeEnum = 3072
	RSA4096 RsaKeySizeEnum = 4096
)

type FormatEnum string

const (
	Str          FormatEnum = "str"
	Hex          FormatEnum = "hex"
	Base64       FormatEnum = "base64"
	Base64Url    FormatEnum = "base64url"
	Base64RawUrl FormatEnum = "base64rawUrl"
)

type KeyFormatEnum string

const (
	PKCS1 KeyFormatEnum = "PKCS1" // 格式: RSA PRIVATE KEY
	PKCS8 KeyFormatEnum = "PKCS8" // 格式: PRIVATE KEY
)

type PemTypeEnum string

const (
	PrivatePKCS1Pem PemTypeEnum = "RSA PRIVATE KEY"
	PublicPKCS1Pem  PemTypeEnum = "RSA PUBLIC KEY"
	PrivatePKCS8Pem PemTypeEnum = "PRIVATE KEY"
	PublicPKCS8Pem  PemTypeEnum = "PUBLIC KEY"
)

func PublicPemList() []PemTypeEnum {
	return []PemTypeEnum{PublicPKCS1Pem, PublicPKCS8Pem}
}

func PrivatePemList() []PemTypeEnum {
	return []PemTypeEnum{PrivatePKCS1Pem, PrivatePKCS8Pem}
}
