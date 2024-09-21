package logic

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"jungler/security"
	"os"
	"path/filepath"
	"strings"
)

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
func (s *ApiKeyStorage) LoadKeys(filename string, password string) (*ApiKeyStorage, error) {
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
		id := string(security.DecryptIt(idBytes, password))
		data := string(security.DecryptIt(dataBytes, password))
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
func (s *ApiKeyStorage) SaveKeys(storage *ApiKeyStorage, filename string, password string) error {
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
		encryptedID := base64.StdEncoding.EncodeToString(security.EncryptIt([]byte(id), password))
		encryptedData := base64.StdEncoding.EncodeToString(security.EncryptIt([]byte(key.GetData()), password))
		_, err = writer.WriteString(encryptedID + ":" + encryptedData + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}
