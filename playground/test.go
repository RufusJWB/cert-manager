package main

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"time"
)

func RandomByte(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func main() {

	senderOrganization := "Siemens"
	senderCommonName := "CloudCA-Integration-Test-User"

	recipientCommonName := "CloudPKI-Integration-Test"

	randomSalt, err := RandomByte(16)
	if err != nil {
		fmt.Println(err)
		return
	}

	randomTransactionID, err := RandomByte(16)
	if err != nil {
		fmt.Println(err)
		return
	}

	randomSenderNonce, err := RandomByte(16)
	if err != nil {
		fmt.Println(err)
		return
	}

	senderDN := Name{
		[]pkix.AttributeTypeAndValue{
			{Type: oidOrganization, Value: senderOrganization}},
		[]pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: senderCommonName}}}

	recipientDN := Name{
		[]pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: recipientCommonName}}}

	requestMessage := PKIMessage{
		Header: PKIHeader{
			PVNO:        CMP2000,
			Sender:      (senderDN).GeneralName(directoryName),
			Recipient:   (recipientDN).GeneralName(directoryName),
			MessageTime: time.Now(),
			ProtectionAlg: AlgorithmIdentifier{
				Algorithm: oidPBM,
				Parameters: PBMParameter{
					Salt: randomSalt,
					OWF: AlgorithmIdentifier{
						Algorithm:  oidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 1024, // Increase significantly for production!!!
					MAC: AlgorithmIdentifier{
						Algorithm:  oidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:    KeyIdentifier(senderDN.String()),
			RecipientKID: KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce: randomSenderNonce,
			RecipNonce: []byte{},
		},
		Body:       []int{},
		Protection: PKIProtection{},
		ExtraCerts: []CMPCertificate{},
	}

	bytes1, err1 := asn1.Marshal(requestMessage)
	if err1 != nil {
		fmt.Println("Error marshaling structure 1:", err1)
		return
	}

	base64Str1 := base64.StdEncoding.EncodeToString(bytes1)
	fmt.Println(base64Str1)

}
