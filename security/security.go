package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"log"
	"fmt"
	"io"
)

// decryptIt decrypts the ciphered text using the key phrase
func DecryptIt(ciphered []byte, keyPhrase string) []byte {
	aesBlock, err := aes.NewCipher([]byte(mdHashing(keyPhrase)))
	if err != nil {
		log.Fatalln(err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Fatalln(err)
	}

	nonceSize := gcmInstance.NonceSize()
	nonce, cipheredText := ciphered[:nonceSize], ciphered[nonceSize:]

	originalText, err := gcmInstance.Open(nil, nonce, cipheredText, nil)
	if err != nil {
		fmt.Println("Error while decrypting, wrong password")
		return nil
	}
	return originalText
}

// mdHashing returns the MD5 hash of the input string
func mdHashing(input string) string {
	byteInput := []byte(input)
	md5Hash := md5.Sum(byteInput)
	return hex.EncodeToString(md5Hash[:])
}

// encryptIt encrypts the value using the key phrase
func EncryptIt(value []byte, keyPhrase string) []byte {
	aesBlock, err := aes.NewCipher([]byte(mdHashing(keyPhrase)))
	if err != nil {
		log.Fatalln(err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		log.Fatalln(err)
	}

	nonce := make([]byte, gcmInstance.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)

	return gcmInstance.Seal(nonce, nonce, value, nil)
}
