// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package voynicrypto

import (
	"encoding/pem"
	"errors"
)

// BoxLoader loads the box encryption/decryption.
type BoxLoader struct {
	KID        string
	PrivateKey KeyLoader
	PublicKey  KeyLoader
}

func (boxLoader *BoxLoader) getBoxPrivateKey() ([32]byte, error) {
	var privateKey [32]byte
	data, err := boxLoader.PrivateKey.GetBytes()
	if err != nil {
		return privateKey, nil
	}
	privatePem, _ := pem.Decode(data)
	if privatePem.Type != "BOX PRIVATE KEY" {
		return privateKey, errors.New("incorrect pem type: " + privatePem.Type)
	}
	copy(privateKey[0:32], privatePem.Bytes[:])
	return privateKey, nil
}

func (boxLoader *BoxLoader) getBoxPublicKey() ([32]byte, error) {
	var publicKey [32]byte
	data, err := boxLoader.PublicKey.GetBytes()
	if err != nil {
		return publicKey, nil
	}
	publicPem, _ := pem.Decode(data)
	if publicPem.Type != "BOX PUBLIC KEY" {
		return publicKey, errors.New("incorrect pem type: " + publicPem.Type)
	}
	copy(publicKey[0:32], publicPem.Bytes[:])
	return publicKey, nil
}

// LoadEncrypt loads an encrypter for the box algorithm.
func (boxLoader *BoxLoader) LoadEncrypt() (Encrypt, error) {
	publicKey, err := boxLoader.getBoxPublicKey()
	if err != nil {
		return nil, err
	}

	privateKey, err := boxLoader.getBoxPrivateKey()
	if err != nil {
		return nil, err
	}
	return NewBoxEncrypter(privateKey, publicKey, boxLoader.KID), nil
}

// LoadDecrypt loads a decrypter for the box algorithm.
func (boxLoader *BoxLoader) LoadDecrypt() (Decrypt, error) {
	publicKey, err := boxLoader.getBoxPublicKey()
	if err != nil {
		return nil, err
	}

	privateKey, err := boxLoader.getBoxPrivateKey()
	if err != nil {
		return nil, err
	}
	return NewBoxDecrypter(privateKey, publicKey, boxLoader.KID), nil
}
