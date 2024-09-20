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
	"strings"
)

var password = ""

type ApiKey struct {
	data string
}

func (a *ApiKey) SetData(data string) {
	a.data = data
}

func (a *ApiKey) GetData() string {
	return a.data
}

type ApiKeyStorage struct {
	keys map[string]ApiKey
}

func NewApiKeyStorage() *ApiKeyStorage {
	return &ApiKeyStorage{
		keys: make(map[string]ApiKey),
	}
}

func (s *ApiKeyStorage) AddKey(id string, key ApiKey) {
	s.keys[id] = key
}

func (s *ApiKeyStorage) GetKey(id string) (ApiKey, bool) {
	key, exists := s.keys[id]
	return key, exists
}

func (s *ApiKeyStorage) DeleteKey(id string) {
	if _, exists := s.keys[id]; !exists {
		return
	}
	delete(s.keys, id)
}

func (s *ApiKeyStorage) LoadKeys(filename string) (*ApiKeyStorage, error) {
	s = NewApiKeyStorage()

	// file, err := os.Open(filename)
	// if err != nil {
	// 	return nil, err
	// }
	// defer file.Close()

	hashingFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer hashingFile.Close()

	// scanner := bufio.NewScanner(file)
	scanerDecrypted := bufio.NewScanner(hashingFile)
	// for scanner.Scan() {
	// 	line := scanner.Text()
	// 	parts := strings.SplitN(line, ":", 2)
	// 	if len(parts) != 2 {
	// 		continue
	// 	}
	// 	id := parts[0]
	// 	data := parts[1]
	// 	s.AddKey(id, ApiKey{data: data})
	// }

	for scanerDecrypted.Scan() {
		line := scanerDecrypted.Text()
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

	// if err := scanner.Err(); err != nil {
	// 	return nil, err
	// }

	if err := scanerDecrypted.Err(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *ApiKeyStorage) SaveKeys(storage *ApiKeyStorage, filename string) error {
	// file, err := os.Create(filename)
	// if err != nil {
	// 	return err
	// }
	// defer file.Close()

	hashingFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file")
		return err
	}
	defer hashingFile.Close()

	// writer := bufio.NewWriter(file)
	hashingWriter := bufio.NewWriter(hashingFile)
	for id, key := range storage.keys {
		// _, err := writer.WriteString(id + ":" + key.GetData() + "\n")
		// _, err = hashingWriter.WriteString(string(encryptIt([]byte(id), password)) + ":" + string(encryptIt([]byte(key.GetData()), password)) + "\n")
		encryptedID := base64.StdEncoding.EncodeToString(encryptIt([]byte(id), password))
		encryptedData := base64.StdEncoding.EncodeToString(encryptIt([]byte(key.GetData()), password))
		_, err = hashingWriter.WriteString(encryptedID + ":" + encryptedData + "\n")
		if err != nil {
			return err
		}
	}

	return hashingWriter.Flush()
	// return writer.Flush()
}

func mdHashing(input string) string {
	byteInput := []byte(input)
	md5Hash := md5.Sum(byteInput)
	return hex.EncodeToString(md5Hash[:]) // by referring to it as a string
}

func encryptIt(value []byte, keyPhrase string) []byte {

	aesBlock, err := aes.NewCipher([]byte(mdHashing(keyPhrase)))
	if err != nil {
		fmt.Println(err)
	}

	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		fmt.Println(err)
	}

	nonce := make([]byte, gcmInstance.NonceSize())
	_, _ = io.ReadFull(rand.Reader, nonce)

	cipheredText := gcmInstance.Seal(nonce, nonce, value, nil)

	return cipheredText
}

func decryptIt(ciphered []byte, keyPhrase string) []byte {
	hashedPhrase := mdHashing(keyPhrase)
	aesBlock, err := aes.NewCipher([]byte(hashedPhrase))
	if err != nil {
		fmt.Println("Error while creating new cipher")
		log.Fatalln(err)
	}
	gcmInstance, err := cipher.NewGCM(aesBlock)
	if err != nil {
		fmt.Println("Error while creating new GCM")
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
	// create a new ApiKeyStorage

	// get password from environment variable
	passwordUser := os.Getenv("JUGGLER_PASSWORD")
	if passwordUser == "" {
		fmt.Println("JUGGLER_PASSWORD environment variable not set")
		return
	}
	password = passwordUser

	args := os.Args[1:]

	if len(args) < 2 {
		fmt.Println("Usage: ./juggler <command> <key> [value]")
		return
	}

	command := args[0]
	key := args[1]

	storage := NewApiKeyStorage()
	storage, err := storage.LoadKeys("data.jnglr")
	if err != nil {
		fmt.Println("Error loading keys:", err)
		fmt.Println("jnglr file not found")
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
		err := storage.SaveKeys(storage, "data.jnglr")
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
		fmt.Println("Key:", apiKey.GetData())
	case "delete":
		storage.DeleteKey(key)
		err := storage.SaveKeys(storage, "data.jnglr")
		if err != nil {
			fmt.Println("Error delete key:", err)
			return
		}
	default:
		fmt.Println("Unknown command. Use 'set' or 'get'")
	}

	// storage := NewApiKeyStorage()
	// st, _ := storage.LoadKeys("data.jnglr")
	// for k, v := range st.keys {
	// 	fmt.Println(k, v)
	// }

	// // add a new ApiKey to the storage
	// storage.AddKey("1", ApiKey{data: "SomeApiKeyData"})
	// // get the ApiKey from the storage
	// key, exists := storage.GetKey("1")
	// if exists {
	// 	fmt.Println("Key exists:", key.GetData())
	// } else {
	// 	fmt.Println("Key does not exist")
	// }
	// // delete the ApiKey from the storage
	// storage.DeleteKey("1")
}

/*
Жонглер ключей API
Вам нужно реализовать хранилище ключей API, которое позволяет добавлять, получать и удалять ключи API.
Каждый ключ API представлен структурой ApiKey, которая содержит строку data.
Хранилище ключей API представлено структурой ApiKeyStorage, которая содержит карту ключей API,
где ключом является строка и значением является ключ API.
Вам нужно реализовать следующие методы для хранилища ключей API:
- NewApiKeyStorage() *ApiKeyStorage - создает новое хранилище ключей API.
- AddKey(id string, key ApiKey) - добавляет ключ API в хранилище по указанному идентификатору.
- GetKey(id string) (ApiKey, bool) - возвращает ключ API из хранилища по указанному идентификатору.
- DeleteKey(id string) - удаляет ключ API из хранилища по указанному идентификатору.
- LoadKeys(filename string) (*ApiKeyStorage, error) - загружает ключи API из файла и возвращает новое хранилище ключей API.
- SaveKeys(storage *ApiKeyStorage, filename string) error - сохраняет ключи API в файл.
*/
