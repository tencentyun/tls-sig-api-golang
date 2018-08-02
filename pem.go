package TLSSigAPI

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var (
	ErrorInvalidKeyType = errors.New("invalid key type")
)

func readPrivateKey(privateKey string) (*ecdsa.PrivateKey, error) {
	var restPem []byte
	restPem = []byte(privateKey)
	for len(restPem) > 0 {
		var block *pem.Block
		block, restPem = pem.Decode(restPem)
		if block == nil {
			break
		}
		switch block.Type {
		case "EC PRIVATE KEY": // pkcs1
			return x509.ParseECPrivateKey(block.Bytes)
		case "PRIVATE KEY": // pkcs8
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err == nil {
				switch key.(type) {
				case *ecdsa.PrivateKey:
					return key.(*ecdsa.PrivateKey), err
				default:
					return nil, ErrorInvalidKeyType
				}
			} else {
				return nil, err
			}
		case "EC PARAMETERS":
			break
		default:
			return nil, ErrorInvalidKeyType
		}
	}
	return nil, errors.New("invalid pem")
}

func readPublicKey(publicKey string) (*ecdsa.PublicKey, error) {
	var restPem []byte
	restPem = []byte(publicKey)
	for len(restPem) > 0 {
		var block *pem.Block
		block, restPem = pem.Decode(restPem)
		if block == nil {
			break
		}
		switch block.Type {
		case "PUBLIC KEY": // pkcs1
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err == nil {
				switch key.(type) {
				case *ecdsa.PublicKey:
					return key.(*ecdsa.PublicKey), nil
				default:
					return nil, ErrorInvalidKeyType
				}
			} else {
				return nil, err
			}
		default:
			return nil, ErrorInvalidKeyType
		}
	}
	return nil, errors.New("invalid pem")
}
