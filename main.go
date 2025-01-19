package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

var filename string

type licensefile struct {
	expiry_date string
}

func (eg *licensefile) licenseinput(date *string) {
	fmt.Println("Enter the expiry date of the license file in YYYY-MM-DD format:")
	fmt.Scanln(&eg.expiry_date)
	*date = eg.expiry_date
}
func (eg *licensefile) OAWfile(date *string) {
	//opening and writing license file

	fmt.Println("Enter the filename with type:")
	fmt.Scanln(&filename)
	file, err := os.OpenFile(filename, os.O_WRONLY, 0644)

	if err != nil {
		fmt.Println("Error in opening the file")
	}

	file.WriteString("expiry_date:")
	file.WriteString(*date)
	file.WriteString("\n")
}

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

// validation of license AK
func validateLicense(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("error opening the file: %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return false, fmt.Errorf("error reading the file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "expiry_date:") {
			dateStr := strings.TrimSpace(strings.TrimPrefix(line, "expiry_date:"))
			expiryDate, err := time.Parse("2006-01-02", dateStr)
			if err != nil {
				return false, fmt.Errorf("invalid date format in the file: %w", err)
			}

			if time.Now().Before(expiryDate) {
				return true, nil
			}
			return false, nil
		}
	}
	return false, fmt.Errorf("expiry_date not found in the file")
}

// checing if the License file exists or no

func checkFileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

// If the validation is true now the contents in the file will be shown

func displaycontentinfile(filepath string) error {

	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("error while opening the file !! : %w", err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("error while reading the file !! : %w ", err)

	}

	fmt.Println("Input given by user :")

	fmt.Println(string(content))
	return nil

}

func main() {

	lcfile := licensefile{}
	var temp1 string
	lcfile.licenseinput(&temp1)
	fmt.Printf("The expiry date of the license file is %s \n", temp1)
	lcfile.OAWfile(&temp1)
	//

	key := []byte("Examplekey123456")

	//encrypting the file

	err := encryptfile(filename, "encrypted.txt", key)

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

	// validation of license
	valid, err := validateLicense(filename)
	if err != nil {
		fmt.Println("Error validating the license:", err)
		return
	}

	// to display the contents present inside the file

	if valid {
		fmt.Println("------------------------------------------")
		fmt.Println(" License is valid. Access granted.\n", "displaying the contents inside the file:")
		fmt.Println("-----------------------------------------")
		err := displaycontentinfile(filename)
		if err != nil {
			fmt.Println("error while displaying the file : %w", err)
		}
	} else {
		fmt.Println("License has expired. Access denied !!! .")
	}

	// file checking for every 24 hours
	if checkFileExists(filename) {
		fmt.Println("File exists.")
	} else {

		fmt.Println("File does not exist.")
	}

	time.Sleep(10 * time.Second)

}
