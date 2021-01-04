/**
 * Copyright 2019 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package voynicrypto

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/webpa-common/logging"
)

func TestBasicCipherLoader(t *testing.T) {
	assert := assert.New(t)

	dir, err := os.Getwd()
	assert.Nil(err)

	encrypter, err := (&RSALoader{
		Hash: &BasicHashLoader{HashName: "SHA512"},
		PrivateKey: &FileLoader{
			Path: dir + string(os.PathSeparator) + "private.pem",
		},
		PublicKey: &FileLoader{
			Path: dir + string(os.PathSeparator) + "public.pem",
		},
	}).LoadEncrypt()
	assert.NotEmpty(encrypter)
	assert.Nil(err)

	decrypter, err := (&RSALoader{
		Hash: &BasicHashLoader{HashName: "SHA512"},
		PrivateKey: &FileLoader{
			Path: dir + string(os.PathSeparator) + "private.pem",
		},
		PublicKey: &FileLoader{
			Path: dir + string(os.PathSeparator) + "public.pem",
		},
	}).LoadDecrypt()
	assert.NotEmpty(decrypter)
	assert.Nil(err)

	message := []byte("Hello World")

	encodedMSG, nonce, err := encrypter.EncryptMessage(message)
	assert.Nil(err)
	assert.NotEmpty(encodedMSG)

	msg, err := decrypter.DecryptMessage(encodedMSG, nonce)
	assert.Nil(err)
	assert.Equal(message, msg)
}

func TestLoadOptions(t *testing.T) {
	require := require.New(t)

	dir, err := os.Getwd()
	require.Nil(err)

	testData := []struct {
		description string
		config      Config
		errOnLarge  bool
	}{
		{"noop", Config{Type: None}, false},
		{"basic", Config{
			Logger: logging.NewTestLogger(nil, t),
			Type:   RSAAsymmetric,
			Params: map[string]string{"hash": "SHA512"},
			KID:    "neato",
			Keys: map[KeyType]string{
				SenderPrivateKey:    dir + string(os.PathSeparator) + "private.pem",
				SenderPublicKey:     dir + string(os.PathSeparator) + "public.pem",
				RecipientPrivateKey: dir + string(os.PathSeparator) + "private.pem",
				RecipientPublicKey:  dir + string(os.PathSeparator) + "public.pem",
			},
		}, true},
		{"box", Config{
			Logger: logging.NewTestLogger(nil, t),
			Type:   Box,
			KID:    "coolio",
			Keys: map[KeyType]string{
				SenderPrivateKey:    dir + string(os.PathSeparator) + "sendBoxPrivate.pem",
				SenderPublicKey:     dir + string(os.PathSeparator) + "sendBoxPublic.pem",
				RecipientPrivateKey: dir + string(os.PathSeparator) + "boxPrivate.pem",
				RecipientPublicKey:  dir + string(os.PathSeparator) + "boxPublic.pem",
			},
		}, true},
	}

	for _, tc := range testData {
		t.Run(tc.description, func(t *testing.T) {
			testOptions(t, tc.config, tc.errOnLarge)
		})
	}
}

func testOptions(t *testing.T, c Config, errOnLarge bool) {
	require := require.New(t)

	encrypter, err := c.LoadEncrypt()
	require.Nil(err)

	decrypter, err := c.LoadDecrypt()
	require.Nil(err)

	testCryptoPair(t, encrypter, decrypter, errOnLarge)
}
