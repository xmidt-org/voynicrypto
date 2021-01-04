package voynicrypto

import (
	"fmt"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/webpa-common/logging"
)

func TestViper(t *testing.T) {
	assert := assert.New(t)

	v := viper.New()
	path, err := os.Getwd()
	assert.Nil(err)
	v.AddConfigPath(path)
	v.SetConfigName("example")

	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("%s\n", err)
	}

	options, err := FromViper(v)
	assert.Nil(err)

	encrypter, err := options.GetEncrypter(logging.NewTestLogger(nil, t))
	assert.Nil(err)
	assert.NotNil(encrypter)

	msg := "hello"
	data, _, err := encrypter.EncryptMessage([]byte(msg))
	assert.Nil(err)
	assert.NotEqual([]byte(msg), data)
}

func TestNOOPViper(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	v := viper.New()
	path, err := os.Getwd()
	assert.Nil(err)
	v.AddConfigPath(path)
	v.SetConfigName("noop")

	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("%s\n", err)
	}

	options, err := FromViper(v)
	require.Nil(err)

	encrypter, err := options.GetEncrypter(logging.NewTestLogger(nil, t))
	require.Nil(err)
	require.NotNil(encrypter)

	msg := "hello"
	data, _, err := encrypter.EncryptMessage([]byte(msg))
	assert.Nil(err)
	assert.Equal([]byte(msg), data)
}

func TestBoxBothSides(t *testing.T) {
	assert := assert.New(t)

	vSend := viper.New()
	path, err := os.Getwd()
	assert.Nil(err)
	vSend.AddConfigPath(path)
	vSend.SetConfigName("boxSender")
	if err := vSend.ReadInConfig(); err != nil {
		t.Fatalf("%s\n", err)
	}

	options, err := FromViper(vSend)
	assert.Nil(err)

	encrypter, err := options.GetEncrypter(logging.NewTestLogger(nil, t))
	assert.Nil(err)

	vRec := viper.New()
	assert.Nil(err)
	vRec.AddConfigPath(path)
	vRec.SetConfigName("boxRecipient")
	if err := vRec.ReadInConfig(); err != nil {
		t.Fatalf("%s\n", err)
	}

	options, err = FromViper(vRec)
	assert.Nil(err)

	decrypters := PopulateCiphers(options, logging.NewTestLogger(nil, t))

	assert.Nil(err)

	msg := []byte("hello")
	data, nonce, err := encrypter.EncryptMessage(msg)
	assert.Nil(err)

	if decrypter, ok := decrypters.Get(encrypter.GetAlgorithm(), encrypter.GetKID()); ok {
		decodedMSG, err := decrypter.DecryptMessage(data, nonce)
		assert.Nil(err)

		assert.Equal(msg, decodedMSG)
	} else {
		assert.Fail("failed to get decrypter with kid")
	}
}

func TestGetDecrypterErr(t *testing.T) {
	assert := assert.New(t)

	vSend := viper.New()
	path, err := os.Getwd()
	assert.Nil(err)
	vSend.AddConfigPath(path)
	vSend.SetConfigName("boxRecipient")
	if err := vSend.ReadInConfig(); err != nil {
		t.Fatalf("%s\n", err)
	}

	options, err := FromViper(vSend)
	assert.Nil(err)

	decrypters := PopulateCiphers(options, logging.NewTestLogger(nil, t))
	fmt.Printf("%#v\n", decrypters)

	decrypter, ok := decrypters.Get(Box, "test")
	assert.True(ok)
	assert.NotNil(decrypter)

	decrypter, ok = decrypters.Get(None, "none")
	assert.True(ok)
	assert.NotNil(decrypter)

	// negative test
	decrypter, ok = decrypters.Get(None, "neato")
	assert.False(ok)
	assert.Nil(decrypter)

	decrypter, ok = decrypters.Get(RSAAsymmetric, "testing")
	assert.False(ok)
	assert.Nil(decrypter)
}
