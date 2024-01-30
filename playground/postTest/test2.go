package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
)

func createRandom(n int) (randomValue []byte, err error) {
	randomValue = make([]byte, n)
	nRead, err := rand.Read(randomValue)

	if err != nil {
		fmt.Errorf("Read err %v", err)
	}
	if nRead != n {
		fmt.Errorf("Read returned unexpected n; %d != %d", nRead, n)
	}
	return
}

func main() {
	senderCommonName := "CloudCA-Integration-Test-User"
	_ = senderCommonName

	recipientCommonName := "CloudPKI-Integration-Test"
	_ = recipientCommonName

	sharedSecret := "SiemensIT"
	_ = sharedSecret

	url := "https://broker.sdo-qa.siemens.cloud/.well-known/cmp"

	randomSalt, _ := createRandom(16)

	client := &http.Client{}

	resp, err := client.Post(url, "application/pkixcmp", nil)

	_ = randomSalt

	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	fmt.Println("Response status:", resp.Status)
	fmt.Println("Response body:", base64.URLEncoding.EncodeToString(body))

}