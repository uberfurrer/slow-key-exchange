package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Side is one of sides for handshake
type Side struct {
	key      *rsa.PrivateKey
	password []byte
}

// GenClientKey makes new rsa keypair for client
func (s *Side) GenClientKey() (err error) {
	s.key, err = rsa.GenerateKey(rand.Reader, 2048)
	return err
}

// GenServerKey makes new rsa keypair for server
func (s *Side) GenServerKey() (err error) {
	s.key, err = rsa.GenerateKey(rand.Reader, 4096)
	return err
}

// PublicKey returns instance of rsa.PublicKey
func (s Side) PublicKey() rsa.PublicKey {
	return s.key.PublicKey
}

// PublicKeyBytes encodes PublicKey to binary blob
func (s Side) PublicKeyBytes() []byte {
	data := s.PublicKey().N.Bytes()
	expByteLen := 8
	expBytes := make([]byte, expByteLen, expByteLen)
	binary.BigEndian.PutUint64(expBytes, uint64(s.PublicKey().E))
	data = append(data, expBytes...)
	return data

}

// Handshake is example for key exchange algorithm
func Handshake(a, b *Side) ([]byte, error) {
	// a means server, b - client

	err := a.GenServerKey()
	if err != nil {
		return nil, err
	}
	err = b.GenClientKey()
	if err != nil {
		return nil, err
	}

	// step 1: get server public key, marshal own public key and XOR it with password

	serverPubkey := a.PublicKey()
	clientPubkeyBytes := b.PublicKeyBytes()

	for i := 0; i < len([]byte(b.password)); i++ {
		clientPubkeyBytes[i] ^= []byte(b.password)[i]
	}

	// encrypted client public key with XORed password
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &serverPubkey, clientPubkeyBytes)
	if err != nil {
		return nil, err
	}

	// step 2: server decrypt client public key and XOR it with password
	// if password was same, server gets correct client public key
	// otherwise client could not decrypt sent session information

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, a.key, encrypted)
	if err != nil {
		return nil, err
	}

	for i := 0; i < len([]byte(a.password)); i++ {
		decrypted[i] ^= []byte(a.password)[i]
	}

	clientN := big.NewInt(0).SetBytes(decrypted[:256])
	clientE := binary.BigEndian.Uint64(decrypted[256:])
	restoredClientPubkey := rsa.PublicKey{
		N: clientN,
		E: int(clientE),
	}

	// step 3: create session key, encrypt it with client PublicKey and sent to him
	const sessionKey = "12345678"

	sessionInfoEncrypted, err := rsa.EncryptPKCS1v15(rand.Reader, &restoredClientPubkey, []byte(sessionKey))
	if err != nil {
		return nil, err
	}

	// step 4: client receive session key

	sessionInfoDecrypted, err := rsa.DecryptPKCS1v15(rand.Reader, b.key, sessionInfoEncrypted)
	if err != nil {
		return nil, err
	}
	return sessionInfoDecrypted, nil

}

func main() {
	server := Side{
		password: []byte("test_password"),
	}
	client := Side{
		password: []byte("test_password"),
	}
	sessionKey, err := Handshake(&server, &client)
	fmt.Println(string(sessionKey), err)

}
