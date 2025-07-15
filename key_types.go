// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package voynicrypto

// KeyType is an enum for how the key can be used.
type KeyType string

const (
	PublicKey           KeyType = "publicKey"
	PrivateKey          KeyType = "privateKey"
	SenderPrivateKey    KeyType = "senderPrivateKey"
	SenderPublicKey     KeyType = "senderPublicKey"
	RecipientPrivateKey KeyType = "recipientPrivateKey"
	RecipientPublicKey  KeyType = "recipientPublicKey"
)

func hasBothEncryptKeys(data map[KeyType]string) bool {
	_, privateOK := data[SenderPrivateKey]
	_, publicOK := data[RecipientPublicKey]
	return privateOK && publicOK
}

func hasBothDecryptKeys(data map[KeyType]string) bool {
	_, privateOK := data[RecipientPrivateKey]
	_, publicOK := data[SenderPublicKey]
	return privateOK && publicOK
}
