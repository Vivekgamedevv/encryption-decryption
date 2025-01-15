package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
)

func encryptfile(inputfile, outputfile string, key []byte) error {

	// opening and reading the input file
	file, err := os.Open(inputfile)
	if err != nil {
		fmt.Println("Error in opening the input file")
	}

	defer file.Close()

	plaintext, err := io.ReadAll(file)

	if err != nil {
		fmt.Println("Error in reading the file")
	}

	//creating a cypher block

	block, err := aes.NewCipher(key)

	if err != nil {
		fmt.Println("Error in creating cypher block")
	}

	//creating a GCM

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		fmt.Println("Error in creating GCM")
	}

	//creating noice
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("Error in generating nonce")
	}

	if err != nil {
		fmt.Println("Error in generating nonce")
	}

	//Sealing the GCM
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	//CREATING AND WRITING TO OUTPUT FILE
	opfile, err := os.Create(outputfile)
	if err != nil {
		fmt.Println("Error in creating the outputfile")
	}
	defer opfile.Close()

	if err != nil {
		fmt.Println("Error in creating outputfile")
	}

	if _, err := opfile.Write(ciphertext); err != nil {
		fmt.Println("Error in writing outputfile")
	}

	return nil
}

func decryptfile(inputfile, outputfile string, key []byte) error {

	// opening and reading the input file

	file, _ := os.Open(inputfile)

	defer file.Close()

	cipherText, err := io.ReadAll(file)

	if err != nil {
		fmt.Println("Error in reading the file")
	}

	//creating a cypher block

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("Error in creating cypher block")
	}

	//creating a GCM

	gcm, err := cipher.NewGCM(block)

	if err != nil {
		fmt.Println("Error in creating GCM")
	}

	//Extracting the noice
	nonceSize := gcm.NonceSize()

	if len(cipherText) < nonceSize {
		fmt.Println("Cypher text is too short")
	}
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	//Opening the GCM

	plaintext, err := gcm.Open(nil, nonce, cipherText, nil)

	if err != nil {
		fmt.Println("Error in decrypting the data")
	}

	//CREATING AND WRITING TO OUTPUT FILE

	opfile, err := os.Create(outputfile)
	if err != nil {
		fmt.Println("Error in creating the output file")
	}
	defer opfile.Close()

	if _, err := opfile.Write(plaintext); err != nil {
		fmt.Println("Error in writing the output file")
	}
	return nil
}

func main() {

	key := []byte("Examplekey123456")

	//encrypting the file

	err := encryptfile("License.txt", "encrypted.txt", key)

	if err != nil {
		fmt.Println("Error in encryrpting the file")
		panic(err)
	}
	fmt.Println("File encypted Succesfully")

	//decrypting the file
	err2 := decryptfile("encrypted.txt", "Decryptedfile", key)

	if err2 != nil {
		fmt.Println("Error in decrypting the file")
	}

	fmt.Println("File decrypted succesfully")

}
