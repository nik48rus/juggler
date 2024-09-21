package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

// DecryptIt decrypts the given ciphered text using the provided key phrase.
// It uses AES encryption in GCM mode for decryption.
//
// Parameters:
//   - ciphered: The encrypted data as a byte slice.
//   - keyPhrase: The key phrase used for decryption.
//
// Returns:
//   - The decrypted original text as a byte slice. If decryption fails, it returns nil.
//
// Note:
//   - The function logs a fatal error if there is an issue creating the AES cipher or GCM instance.
//   - If the decryption fails due to an incorrect password, it prints an error message and returns nil.
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

// mdHashing takes an input string, computes its MD5 hash, and returns the hash as a hexadecimal string.
//
// Parameters:
// - input: The string to be hashed.
//
// Returns:
// - A hexadecimal string representation of the MD5 hash of the input.
func mdHashing(input string) string {
	byteInput := []byte(input)
	md5Hash := md5.Sum(byteInput)
	return hex.EncodeToString(md5Hash[:])
}

// EncryptIt encrypts the given byte slice using AES encryption with the provided key phrase.
// It returns the encrypted byte slice.
//
// Parameters:
//   - value: The byte slice to be encrypted.
//   - keyPhrase: The key phrase used to generate the AES encryption key.
//
// Returns:
//   - The encrypted byte slice.
//
// Note:
//   - The function uses AES-GCM (Galois/Counter Mode) for encryption.
//   - The nonce is generated randomly for each encryption operation.
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
