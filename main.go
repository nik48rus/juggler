package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var password = ""
var file_path = ""

type ApiKey struct {
	data string
}

// SetData sets the data of the ApiKey
func (a *ApiKey) SetData(data string) {
	a.data = data
}

// GetData returns the data of the ApiKey
func (a *ApiKey) GetData() string {
	return a.data
}

type ApiKeyStorage struct {
	keys map[string]ApiKey
}

// NewApiKeyStorage creates a new ApiKeyStorage
func NewApiKeyStorage() *ApiKeyStorage {
	return &ApiKeyStorage{
		keys: make(map[string]ApiKey),
	}
}

// AddKey adds a new key to the storage
func (s *ApiKeyStorage) AddKey(id string, key ApiKey) {
	s.keys[id] = key
}

// GetKey returns the key with the given id
func (s *ApiKeyStorage) GetKey(id string) (ApiKey, bool) {
	key, exists := s.keys[id]
	return key, exists
}

// DeleteKey deletes the key with the given id
func (s *ApiKeyStorage) DeleteKey(id string) {
	delete(s.keys, id)
}

// SaveKeys saves the keys to a file
func (s *ApiKeyStorage) LoadKeys(filename string) (*ApiKeyStorage, error) {
	s = NewApiKeyStorage()

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		encryptedID, encryptedData := parts[0], parts[1]
		idBytes, err := base64.StdEncoding.DecodeString(encryptedID)
		if err != nil {
			return nil, err
		}
		dataBytes, err := base64.StdEncoding.DecodeString(encryptedData)
		if err != nil {
			return nil, err
		}
		id := string(decryptIt(idBytes, password))
		data := string(decryptIt(dataBytes, password))
		if id == "" || data == "" {
			return nil, fmt.Errorf("Invalid data")
		}
		s.AddKey(id, ApiKey{data: data})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return s, nil
}

// SaveKeys saves the keys to a file
func (s *ApiKeyStorage) SaveKeys(storage *ApiKeyStorage, filename string) error {
	fileDir := filepath.Dir(filename)
	if err := os.MkdirAll(fileDir, os.ModePerm); err != nil {
		return err
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for id, key := range storage.keys {
		encryptedID := base64.StdEncoding.EncodeToString(encryptIt([]byte(id), password))
		encryptedData := base64.StdEncoding.EncodeToString(encryptIt([]byte(key.GetData()), password))
		_, err = writer.WriteString(encryptedID + ":" + encryptedData + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}

// mdHashing returns the MD5 hash of the input string
func mdHashing(input string) string {
	byteInput := []byte(input)
	md5Hash := md5.Sum(byteInput)
	return hex.EncodeToString(md5Hash[:])
}

// encryptIt encrypts the value using the key phrase
func encryptIt(value []byte, keyPhrase string) []byte {
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

// decryptIt decrypts the ciphered text using the key phrase
func decryptIt(ciphered []byte, keyPhrase string) []byte {
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

func main() {
	passwordUser := os.Getenv("JUGGLER_PASSWORD")
	if passwordUser == "" {
		fmt.Println("JUGGLER_PASSWORD environment variable not set")
		return
	}
	password = passwordUser

	// JUGGLER_DB_PATH
	db_path := os.Getenv("JUGGLER_DB_PATH")
	if db_path == "" {
		db_path = "./"
	}

	file_path = db_path + "db.jnglr"

	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Println("Usage: ./juggler <command> <key> [value]")
		return
	}

	command := args[0]
	key := args[1]

	storage := NewApiKeyStorage()
	storage, err := storage.LoadKeys(file_path)
	if err != nil {
		fmt.Println("Error loading keys:", err)
		storage = NewApiKeyStorage()
	}

	switch command {
	case "set":
		if len(args) != 3 {
			fmt.Println("Usage: ./juggler save <key> <value>")
			return
		}
		value := args[2]
		storage.AddKey(key, ApiKey{data: value})
		err := storage.SaveKeys(storage, file_path)
		if err != nil {
			fmt.Println("Error saving keys:", err)
			return
		}
		fmt.Println("Key saved successfully")
	case "get":
		apiKey, exists := storage.GetKey(key)
		if !exists {
			fmt.Println("Key not found")
			return
		}
		fmt.Println(apiKey.GetData())
	case "delete":
		storage.DeleteKey(key)
		err := storage.SaveKeys(storage, file_path)
		if err != nil {
			fmt.Println("Error deleting key:", err)
			return
		}
	default:
		fmt.Println("Unknown command. Use 'set' or 'get'")
	}
}

/*
Каждый ключ API представлен структурой ApiKey, которая содержит строку data.
Хранилище ключей API представлено структурой ApiKeyStorage, которая содержит карту ключей API,
где ключом является строка и значением является ключ API.

- NewApiKeyStorage() *ApiKeyStorage - создает новое хранилище ключей API.
- AddKey(id string, key ApiKey) - добавляет ключ API в хранилище по указанному идентификатору.
- GetKey(id string) (ApiKey, bool) - возвращает ключ API из хранилища по указанному идентификатору.
- DeleteKey(id string) - удаляет ключ API из хранилища по указанному идентификатору.
- LoadKeys(filename string) (*ApiKeyStorage, error) - загружает ключи API из файла и возвращает новое хранилище ключей API.
- SaveKeys(storage *ApiKeyStorage, filename string) error - сохраняет ключи API в файл.
*/
