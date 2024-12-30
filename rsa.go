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
	"github.com/dhlanshan/wind/internal/tools"
	"github.com/dhlanshan/wind/internal/utils"
	"math/big"
	"os"
	"path/filepath"
)

type Rsa struct {
	bits        RsaKeySizeEnum    // Key size (e.g., 2048, 4096)
	privateKey  *rsa.PrivateKey   // Private RSA key
	publicKey   *rsa.PublicKey    // Public RSA key
	certificate *x509.Certificate // Certificate corresponding to the public key
}

// GetPrivate returns the RSA private key.
func (r *Rsa) GetPrivate() *rsa.PrivateKey {
	return r.privateKey
}

// GetPublic returns the RSA public key.
func (r *Rsa) GetPublic() *rsa.PublicKey {
	return r.publicKey
}

// GetCert returns the X.509 certificate.
func (r *Rsa) GetCert() *x509.Certificate {
	return r.certificate
}

// GenerateKey generates a new RSA key pair with the specified key size.
func (r *Rsa) GenerateKey(bits RsaKeySizeEnum) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, int(bits))
	if err != nil {
		return errors.New("failed to generate private key: " + err.Error())
	}

	r.bits = bits
	r.privateKey = privateKey
	r.publicKey = &privateKey.PublicKey

	return nil
}

// LoadKey loads an RSA private/public key pair from a PEM-encoded byte slice.
func (r *Rsa) LoadKey(keyPem []byte) error {
	privateKey, publicKey, err := r.parseKey(keyPem)
	if err != nil {
		return err
	}
	if privateKey != nil {
		r.privateKey = privateKey
		r.publicKey = &privateKey.PublicKey
		r.bits = RsaKeySizeEnum(r.privateKey.N.BitLen())
	}
	if publicKey != nil {
		r.publicKey = publicKey
		r.bits = RsaKeySizeEnum(publicKey.N.BitLen())
	}

	return nil
}

// LoadKeyByFile loads an RSA private/public key pair from a PEM-encoded file.
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

// GetKeyStr retrieves the private and public keys in PEM format.
func (r *Rsa) GetKeyStr(format KeyFormatEnum) (priKey, pubKey string, err error) {
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

// SaveKey saves the private and public keys to files in PEM format.
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
	priFile, err := os.Create(filepath.Join(dir, priFn))
	if err != nil {
		return err
	}
	defer priFile.Close()
	if err = pem.Encode(priFile, priBlock); err != nil {
		return err
	}

	pubFn := fmt.Sprintf("%s_public_key.pem", filename)
	pubFile, err := os.Create(filepath.Join(dir, pubFn))
	if err != nil {
		return err
	}
	defer pubFile.Close()
	if err = pem.Encode(pubFile, pubBlock); err != nil {
		return err
	}

	return
}

// GenSerialNumber generates a random serial number for the certificate.
func (r *Rsa) GenSerialNumber() *big.Int {
	maxNum := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	serialNumber, _ := rand.Int(rand.Reader, maxNum)

	return serialNumber
}

// BuildCert generates a certificate from a template and signs it with the parent's private key.
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

// LoadCert loads an RSA certificate from a PEM-encoded byte slice.
func (r *Rsa) LoadCert(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block.Type != "CERTIFICATE" {
		return errors.New("the kind of PEM should be CERTIFICATE")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	r.certificate = cert

	return nil
}

// LoadCertByFile loads an RSA certificate from a PEM-encoded file.
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

// GetCertStr retrieves the certificate in PEM format.
func (r *Rsa) GetCertStr() (cert string, err error) {
	if r.certificate == nil {
		return "", errors.New("certificate is nil")
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.certificate.Raw})), nil
}

// SaveCert saves the certificate to a file in PEM format.
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
	certFile, err := os.Create(filepath.Join(dir, certFn))
	if err != nil {
		return err
	}
	defer certFile.Close()

	return pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: r.certificate.Raw})
}

// Sign signs a message using the private key, the specified signing type, hash type, and format.
func (r *Rsa) Sign(msg []byte, signType SignTypeEnum, hashType HashTypeEnum, format FormatEnum, opts *rsa.PSSOptions) (ciphertext string, err error) {
	if len(msg) == 0 {
		return "", errors.New("message is empty")
	}
	if !tools.InSlice([]SignTypeEnum{PKCS1v15, PSS}, signType) {
		return "", errors.New("invalid sign type")
	}
	if !tools.InSlice([]FormatEnum{Str, Hex, Base64, Base64Url, Base64RawUrl}, format) {
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
	if err != nil {
		return "", err
	}

	ciphertext = utils.PackDataToStr(signData, string(format))

	return
}

// VerifySign verifies the signature of a message using the public key, the signature, and the specified hash type and format.
func (r *Rsa) VerifySign(msg []byte, ciphertext string, signType SignTypeEnum, hashType HashTypeEnum, format FormatEnum, opts *rsa.PSSOptions) (err error) {
	if len(msg) == 0 || ciphertext == "" {
		return errors.New("msg or ciphertext is empty")
	}
	if !tools.InSlice([]SignTypeEnum{PKCS1v15, PSS}, signType) {
		return errors.New("invalid sign type")
	}
	if !tools.InSlice([]FormatEnum{Str, Hex, Base64, Base64Url, Base64RawUrl}, format) {
		return errors.New("invalid format")
	}
	if r.privateKey == nil {
		return errors.New("private key is nil")
	}

	signData, err := utils.PackDataToByte(ciphertext, string(format))
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

// Encrypt encrypts the given plaintext using RSA public key with specified padding, hash type, and format.
// It returns the ciphertext as a string or an error if any issue occurs during encryption.
func (r *Rsa) Encrypt(plainText []byte, padding CryptoPaddingEnum, hashType HashTypeEnum, format FormatEnum, label []byte) (ciphertext string, err error) {
	if len(plainText) == 0 {
		return "", errors.New("plainText is empty")
	}
	if !tools.InSlice([]CryptoPaddingEnum{PKCS1v15Padding, OAEPPadding}, padding) {
		return "", errors.New("invalid padding")
	}
	if !tools.InSlice([]FormatEnum{Str, Hex, Base64, Base64Url, Base64RawUrl}, format) {
		return "", errors.New("invalid format")
	}
	if r.publicKey == nil {
		return "", errors.New("public key is nil")
	}

	hashMap := map[HashTypeEnum]crypto.Hash{Sha1: crypto.SHA1, Sha256: crypto.SHA256, Sha512: crypto.SHA512}
	sha, ok := hashMap[hashType]
	if !ok {
		return "", errors.New("invalid hash type")
	}

	var cipherByte []byte
	switch padding {
	case OAEPPadding:
		cipherByte, err = rsa.EncryptOAEP(sha.New(), rand.Reader, r.publicKey, plainText, label)
	case PKCS1v15Padding:
		cipherByte, err = rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, plainText)
	}
	if err != nil {
		return "", err
	}

	ciphertext = utils.PackDataToStr(cipherByte, string(format))
	return
}

// Decrypt decrypts the given ciphertext using RSA private key with specified padding, hash type, and format.
// It returns the plaintext or an error if any issue occurs during decryption.
func (r *Rsa) Decrypt(ciphertext string, padding CryptoPaddingEnum, hashType HashTypeEnum, format FormatEnum, label []byte) (plainText []byte, err error) {
	if ciphertext == "" {
		return nil, errors.New("ciphertext is empty")
	}
	if !tools.InSlice([]CryptoPaddingEnum{PKCS1v15Padding, OAEPPadding}, padding) {
		return nil, errors.New("invalid padding")
	}
	if !tools.InSlice([]FormatEnum{Str, Hex, Base64, Base64Url, Base64RawUrl}, format) {
		return nil, errors.New("invalid format")
	}
	if r.privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	cipherByte, err := utils.PackDataToByte(ciphertext, string(format))
	if err != nil {
		return nil, err
	}

	hashMap := map[HashTypeEnum]crypto.Hash{Sha1: crypto.SHA1, Sha256: crypto.SHA256, Sha512: crypto.SHA512}
	sha, ok := hashMap[hashType]
	if !ok {
		return nil, errors.New("invalid hash type")
	}

	switch padding {
	case OAEPPadding:
		plainText, err = rsa.DecryptOAEP(sha.New(), rand.Reader, r.privateKey, cipherByte, label)
	case PKCS1v15Padding:
		plainText, err = rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, cipherByte)
	}
	if err != nil {
		return nil, err
	}

	return
}

// marshalKey marshals the private and public keys into PEM format based on the provided key format.
func (r *Rsa) marshalKey(format KeyFormatEnum) (priBlock, pubBlock *pem.Block, err error) {
	var priKeyDer []byte
	var pubKeyDer []byte
	var priType string
	var pubType string

	switch format {
	case PKCS1:
		priKeyDer = x509.MarshalPKCS1PrivateKey(r.privateKey)
		priType, pubType = string(PrivatePKCS1Pem), string(PublicPKCS1Pem)
	case PKCS8:
		priKeyDer, err = x509.MarshalPKCS8PrivateKey(r.privateKey)
		priType, pubType = string(PrivatePKCS8Pem), string(PublicPKCS8Pem)
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

// parseKey parses a PEM-encoded key and returns the corresponding private and public keys.
func (r *Rsa) parseKey(keyPem []byte) (privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode(keyPem)
	if block == nil {
		return nil, nil, errors.New("failed to decode PEM block")
	}

	format := PemTypeEnum(block.Type)
	if tools.InSlice(PrivatePemList(), format) {
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
	} else if tools.InSlice(PublicPemList(), format) {
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

// hashData hashes the input message using the specified hash type.
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
