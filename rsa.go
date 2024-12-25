package wind

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/dhlanshan/wind/internal/tool"
	"github.com/dhlanshan/wind/internal/util"
	"math/big"
	"os"
)

type Rsa struct {
	Bits        RsaKeySizeEnum    // 秘钥大小
	privateKey  *rsa.PrivateKey   // 私钥
	publicKey   *rsa.PublicKey    // 公钥
	certificate *x509.Certificate // 证书
}

func (r *Rsa) GenerateKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, int(r.Bits))
	if err != nil {
		return errors.New("failed to generate private key: " + err.Error())
	}
	r.privateKey = privateKey
	r.publicKey = &privateKey.PublicKey

	return nil
}

func (r *Rsa) LoadKey(keyPem []byte) error {
	privateKey, publicKey, err := r.parseKey(keyPem)
	if err != nil {
		return err
	}
	if privateKey != nil {
		r.privateKey = privateKey
		r.publicKey = &privateKey.PublicKey
	}
	if publicKey != nil {
		r.publicKey = publicKey
	}

	return nil
}

func (r *Rsa) LoadKeyByFile(keyFile string) error {
	if keyFile == "" {
		return errors.New("keyFile is empty")
	}
	keyPem, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	return r.LoadKey(keyPem)
}

func (r *Rsa) GetKey(format KeyFormatEnum) (priKey, pubKey string, err error) {
	if r.privateKey == nil || r.publicKey == nil {
		return "", "", errors.New("private key or public key is nil")
	}

	priBlock, pubBlock, err := r.marshalKey(format)
	if err != nil {
		return "", "", err
	}

	priKey = string(pem.EncodeToMemory(priBlock))
	pubKey = string(pem.EncodeToMemory(pubBlock))

	return
}

func (r *Rsa) SaveKey(format KeyFormatEnum, dir, filename string) (err error) {
	if r.privateKey == nil || r.publicKey == nil {
		return errors.New("private key or public key is nil")
	}
	if dir == "" {
		dir = "."
	}
	if filename == "" {
		filename = "wind"
	}

	priBlock, pubBlock, err := r.marshalKey(format)
	if err != nil {
		return err
	}

	priFn := fmt.Sprintf("%s_private_key.pem", filename)
	priFile, err := os.Create(dir + "/" + priFn)
	if err != nil {
		return err
	}
	defer priFile.Close()
	if err = pem.Encode(priFile, priBlock); err != nil {
		return err
	}

	pubFn := fmt.Sprintf("%s_public_key.pem", filename)
	pubFile, err := os.Create(dir + "/" + pubFn)
	if err != nil {
		return err
	}
	defer pubFile.Close()
	if err = pem.Encode(pubFile, pubBlock); err != nil {
		return err
	}

	return
}

func (r *Rsa) GenSerialNumber() *big.Int {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)))

	return serialNumber
}

func (r *Rsa) BuildCert(template, parentCert *x509.Certificate, parentPrivateKey *rsa.PrivateKey) error {
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, r.publicKey, parentPrivateKey)
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return err
	}

	r.certificate = certificate
	return nil
}

func (r *Rsa) LoadCert(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	r.certificate = cert

	return nil
}

func (r *Rsa) LoadCertByFile(certFile string) error {
	if certFile == "" {
		return errors.New("certFile is empty")
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return err
	}

	return r.LoadCert(certPEM)
}

func (r *Rsa) GetCert() (cert string, err error) {
	if r.certificate == nil {
		return "", errors.New("certificate is nil")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.certificate.Raw})), nil
}

func (r *Rsa) SaveCert(dir, filename string) error {
	if r.certificate == nil {
		return errors.New("certificate is nil")
	}
	if dir == "" {
		dir = "."
	}
	if filename == "" {
		filename = "wind"
	}

	certFn := fmt.Sprintf("%s_cert.pem", filename)
	certFile, err := os.Create(dir + "/" + certFn)
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: r.certificate.Raw})
}

func (r *Rsa) Sign(msg []byte, signType SignTypeEnum, hashType HashTypeEnum, format FormatEnum, opts *rsa.PSSOptions) (ciphertext string, err error) {
	if len(msg) == 0 {
		return "", errors.New("message is empty")
	}
	if !tool.InSlice([]SignTypeEnum{PKCS1v15, PSS}, signType) {
		return "", errors.New("invalid sign type")
	}
	if !tool.InSlice([]FormatEnum{Str, Hex, Base64, Base64Url, Base64RawUrl}, format) {
		return "", errors.New("invalid format")
	}
	if r.privateKey == nil {
		return "", errors.New("private key is nil")
	}

	hashed, sha, err := r.hashData(msg, hashType)
	if err != nil {
		return "", err
	}

	var signData []byte
	switch signType {
	case PKCS1v15:
		signData, err = rsa.SignPKCS1v15(rand.Reader, r.privateKey, sha, hashed)
	case PSS:
		signData, err = rsa.SignPSS(rand.Reader, r.privateKey, sha, hashed, opts)
	}

	ciphertext = util.PackDataToStr(signData, string(format))

	return
}

func (r *Rsa) VerifySign(msg []byte, ciphertext string, signType SignTypeEnum, hashType HashTypeEnum, format FormatEnum, opts *rsa.PSSOptions) (err error) {
	if len(msg) == 0 || ciphertext == "" {
		return errors.New("msg or ciphertext is empty")
	}
	if !tool.InSlice([]SignTypeEnum{PKCS1v15, PSS}, signType) {
		return errors.New("invalid sign type")
	}
	if !tool.InSlice([]FormatEnum{Str, Hex, Base64, Base64Url, Base64RawUrl}, format) {
		return errors.New("invalid format")
	}
	if r.privateKey == nil {
		return errors.New("private key is nil")
	}

	signData, err := util.PackDataToByte(ciphertext, string(format))
	if err != nil {
		return err
	}

	hashed, sha, err := r.hashData(msg, hashType)
	if err != nil {
		return err
	}

	switch signType {
	case PKCS1v15:
		err = rsa.VerifyPKCS1v15(&r.privateKey.PublicKey, sha, hashed, signData)
	case PSS:
		err = rsa.VerifyPSS(&r.privateKey.PublicKey, sha, hashed, signData, opts)
	}

	return
}

func (r *Rsa) marshalKey(format KeyFormatEnum) (priBlock, pubBlock *pem.Block, err error) {
	var priKeyDer []byte
	var pubKeyDer []byte
	var priType string
	var pubType string

	switch format {
	case PKCS1:
		priKeyDer = x509.MarshalPKCS1PrivateKey(r.privateKey)
		priType, pubType = "RSA PRIVATE KEY", "RSA PUBLIC KEY"
	case PKCS8:
		priKeyDer, err = x509.MarshalPKCS8PrivateKey(r.privateKey)
		priType, pubType = "PRIVATE KEY", "PUBLIC KEY"
	default:
		err = fmt.Errorf("unsupported key format: %s", format)
	}
	if err != nil {
		return nil, nil, err
	}

	priBlock = &pem.Block{Type: priType, Bytes: priKeyDer}

	pubKeyDer, err = x509.MarshalPKIXPublicKey(&r.privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubBlock = &pem.Block{Type: pubType, Bytes: pubKeyDer}

	return
}

func (r *Rsa) parseKey(keyPem []byte) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, nil, errors.New("failed to decode PEM block")
	}

	format := PemTypeEnum(block.Type)
	if tool.InSlice(PrivatePemList(), format) {
		switch format {
		case PrivatePKCS1Pem:
			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		case PrivatePKCS8Pem:
			var p8Key any
			p8Key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if pk, ok := p8Key.(*rsa.PrivateKey); ok {
				privateKey = pk
			}
		default:
			err = fmt.Errorf("unsupported key format: %s", format)
		}
	} else if tool.InSlice(PublicPemList(), format) {
		var pub any
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
		if pk, ok := pub.(*rsa.PublicKey); ok {
			publicKey = pk
		}
	} else {
		err = fmt.Errorf("unsupported key format: %s", format)
	}

	if err != nil {
		return nil, nil, err
	}

	return
}

func (r *Rsa) hashData(msg []byte, hashType HashTypeEnum) (hashed []byte, sha crypto.Hash, err error) {
	switch hashType {
	case Sha1:
		sha1Data := sha1.Sum(msg)
		sha = crypto.SHA1
		hashed = sha1Data[:]
	case Sha256:
		sha256Data := sha256.Sum256(msg)
		sha = crypto.SHA256
		hashed = sha256Data[:]
	case Sha512:
		sha512Data := sha512.Sum512(msg)
		sha = crypto.SHA512
		hashed = sha512Data[:]
	default:
		err = fmt.Errorf("unsupported hash type: %s", hashType)
	}

	return
}
