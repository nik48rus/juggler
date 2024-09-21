package main

import (
	"fmt"
	"jungler/logic"
	"os"
)

var password = ""
var file_path = ""

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

	storage := logic.NewApiKeyStorage()
	storage, err := storage.LoadKeys(file_path, password)
	if err != nil {
		fmt.Println("Error loading keys:", err)
		storage = logic.NewApiKeyStorage()
	}

	switch command {
	case "set":
		if len(args) != 3 {
			fmt.Println("Usage: ./juggler save <key> <value>")
			return
		}
		value := args[2]
		api_key := logic.ApiKey{}
		api_key.SetData(value)
		storage.AddKey(key, api_key)
		err := storage.SaveKeys(storage, file_path, password)
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
		err := storage.SaveKeys(storage, file_path, password)
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
