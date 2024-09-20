package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Data struct {
	Message string `json:"message"`
}

func saveJSONToFile(data Data, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(data)
}

func ticker() {
	data := Data{Message: "Hello, World!"}
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := saveJSONToFile(data, "data.json")
			if err != nil {
				fmt.Println("Error saving JSON to file:", err)
			} else {
				fmt.Println("JSON saved to file successfully")
			}
		}
	}
}
