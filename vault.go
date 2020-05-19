package secret

import (
	"errors"

	"github.com/Tak1za/go-secret/encrypt"
)

type Vault struct {
	encodingKey string
	keyValues   map[string]string
}

func NewVault(encodingKey string) Vault {
	return Vault{encodingKey: encodingKey, keyValues: make(map[string]string)}
}

func (v *Vault) Get(key string) (string, error) {
	hex, ok := v.keyValues[key]
	if !ok {
		return "", errors.New("Secret: No value for the key")
	}
	decryptedValue, err := encrypt.Decrypt(v.encodingKey, hex)
	if err != nil {
		return "", errors.New("Secret: Error while decrypting")
	}
	return decryptedValue, nil
}

func (v *Vault) Set(key, value string) error {
	encryptedValue, err := encrypt.Encrypt(v.encodingKey, value)
	if err != nil {
		return err
	}
	v.keyValues[key] = encryptedValue
	return nil
}
