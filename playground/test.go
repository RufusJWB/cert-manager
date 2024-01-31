package main

import (
	"bytes"
	"crypto/rand"
	x509 "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"reflect"
	"time"
)

func main() {

	senderCommonName := "CloudCA-Integration-Test-User"
	_ = senderCommonName

	recipientCommonName := "CloudPKI-Integration-Test"
	_ = recipientCommonName

	sharedSecret := "SiemensIT"
	_ = sharedSecret

	url := "https://broker.sdo-qa.siemens.cloud/.well-known/cmp"

	randomSalt, _ := createRandom(16)
	_ = randomSalt

	randomTransactionID, _ := createRandom(16)
	_ = randomTransactionID

	randomSenderNonce, _ := createRandom(16)
	_ = randomSenderNonce

	randomRecipNonce, _ := createRandom(16)
	_ = randomRecipNonce

	fmt.Println("Request SenderNonce: " + base64.StdEncoding.EncodeToString(randomSenderNonce))
	fmt.Println("Request RecipNonce: " + base64.StdEncoding.EncodeToString(randomRecipNonce))
	fmt.Println("Request TransactionID: " + base64.StdEncoding.EncodeToString(randomTransactionID))

	csr := `-----BEGIN CERTIFICATE REQUEST-----
MIIEwDCCAqgCAQAwGzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJYtP4iLdUBt96pl3Exrz/UXzSuTsZ+i
f7cnoFz+DyzS3+6pPLSS7o37g8xxZlqJecY6CfDeLY40maFIsHM4CgkVldwdy4F7
SByFwVZseozGoWGOSSD2ceSMA6qgKmgSRUqwumLJdOJqc5bDQYQqPYabp66hrm9q
VNGlC33XPJ5btITCTwWp+3LNcUYdAPDsMSY/MF8ejExITKjj8M/Xt82vSxY4VNl8
kkSvwmOSSdfzpyl1MN9+zVslUyGJywQyV4vcLqJrM9C32nnh1SY4oE000GTGSbIa
w5kolzrsSBVmLxuNhrgrg4IHZMaYn1OtrI3yVUXuAU0CENHfpUo20CBjTt43ReBo
2HXPoWbxULUOqIDQQELl3ZMOxjt7owXfm5go7EsqMKbPAKtHGuFZkVe/C6JYheWQ
nl0mGC2yfhEix3zviReTmocLLWAeTz3bVO3+jD3aKliv/RA1zyYIwWycAZuVJ17o
e2ceBnHM0/ccO/3giERqHIn+u8hUduCRIo+S1bEB6/Mf91QYFX63uPkYzs4TW/1I
3pklIOiYCbedVORs+U7GMcgPMOa6+oZHYsd2Q/kFly7K0RfhY/g/YTGkLW4LhXSU
/lplOSZEasTrz5az8cdJK4JL8OAfCe6qN6gKMNNhTJC3AYVa0ATbazGvQdkEHCNn
mFr4VRwVfV2zAgMBAAGgYDBeBgkqhkiG9w0BCQ4xUTBPMAwGA1UdEwEB/wQCMAAw
HQYDVR0OBBYEFIa6xq2GOW+R3JVCWZMwTadF7m+2MAsGA1UdDwQEAwIDuDATBgNV
HSUEDDAKBggrBgEFBQcDAjANBgkqhkiG9w0BAQ0FAAOCAgEAkiXuuU3/dXh3fYX2
agt3JoJ8+GmPSVLvLbwiCkxNnJkI28gpn0BROO+QGUSHRSVaoUM1/GYb1XpXQvDd
LIC5ZC/jlXpC5/PcnvCOQu3YJmEQeDub6YrFcFLMkf1dhOBfEywrEZwfyQ/2tNUZ
FU9yiW0gF015651y8Xl0WMCCi8nsZ19o8MI2zzzafvpyk0M66IYq1GpRM4MzHcnf
YzA4RygZwlrf1fiMjPrzY0oh3U53M1ejGBoAAHSqNJ0rf02FU0U+5M8SaoById8v
ITgegC1Gsga/ox41Leiiinqudije+BX66wze/ZnjKFMfjlg2vBQChzyrTOZ07U2w
T7v8Ey0Go0meB7sjyaKVrJiinI95Woyk/JrvUbTXW6lSVBiTkj+PKQGaGT3otIDo
8HWI35EWs0FoKndUh3MznvsnRycf+7cPoS3prVThmA+bxS1z+pMFwYRFhl63OCQP
kCDAJsS9LESD2wDIrv7Hmxu9SAVwqmil8KMNlwGbBj+MzE9OUUTmL7BQYujVVV8i
MdBk6ysluKbfbolzkPKZxdZHs9YsC3szT8a7U1OY/tABBrF3D6cbEJFZgscuZFgW
LSnod9g7TZsgTN3TY9V6xj6tERl+0/kMTcnQV55UOWAPCQqk0SrwdB9i2ebZCVgQ
1qrQsPB5Gv8K5COmC9b7VY4czB4=
-----END CERTIFICATE REQUEST-----
`
	certificateRequest, _ := pem.Decode([]byte(csr))
	if certificateRequest == nil {
		fmt.Println("failed to decode PEM block containing the CSR")
		return
	}

	csrBytes := certificateRequest.Bytes

	parsedCSR, _ := x509.ParseCertificateRequest(csrBytes)

	csrPublicKey := parsedCSR.PublicKey

	_ = csrPublicKey

	senderDN := Name{
		[]pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: senderCommonName}}}

	recipientDN := Name{
		[]pkix.AttributeTypeAndValue{
			{Type: oidCommonName, Value: recipientCommonName}}}

	p10RequestMessage := PKIMessage{
		Header: PKIHeader{
			PVNO:        CMP2000,
			Sender:      ChoiceConvert(senderDN, directoryName),
			Recipient:   ChoiceConvert(recipientDN, directoryName),
			MessageTime: time.Now(),
			ProtectionAlg: AlgorithmIdentifier{
				Algorithm: oidPBM,
				Parameters: PBMParameter{
					Salt: randomSalt,
					OWF: AlgorithmIdentifier{
						Algorithm:  oidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 262144,
					MAC: AlgorithmIdentifier{
						Algorithm:  oidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:     KeyIdentifier(senderDN.String()),
			RecipientKID:  KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce:   randomSenderNonce,
			RecipNonce:    randomRecipNonce,
		},
		Body: asn1.RawValue{Bytes: certificateRequest.Bytes, IsCompound: true, Class: asn1.ClassContextSpecific, Tag: PKCS10CertificationRequest},
	}

	responseBody := sendCMPMessage(p10RequestMessage, sharedSecret, url)

	var responseMessage PKIMessage
	asn1.Unmarshal(responseBody, &responseMessage)

	responseSenderNonce := responseMessage.Header.SenderNonce
	responseRecipientNonce := responseMessage.Header.RecipNonce
	responseTransactionID := responseMessage.Header.TransactionID

	fmt.Println("Response SenderNonce: " + base64.StdEncoding.EncodeToString(responseSenderNonce))
	fmt.Println("Response RecipNonce: " + base64.StdEncoding.EncodeToString(responseRecipientNonce))
	fmt.Println("Response TransactionID: " + base64.StdEncoding.EncodeToString(responseTransactionID))

	if bytes.Equal(responseTransactionID, randomTransactionID) {
		fmt.Println("TransactionID is equale")
	} else {
		log.Fatal("TransactionID is not equale")
	}

	if bytes.Equal(randomSenderNonce, responseRecipientNonce) {
		fmt.Println("Nonce is equale")
	} else {
		log.Fatal("Nonce is not equale")
	}

	if responseMessage.Body.Tag != CertificationResponse {
		log.Fatalf("Response message of type %v", responseMessage.Body.Tag)
	}

	var certRepMessage CertRepMessage
	asn1.Unmarshal(responseMessage.Body.Bytes, &certRepMessage)

	if len(certRepMessage.Response) != 1 {
		log.Fatalf("Response contained %v certificates", len(certRepMessage.Response))
	}

	if certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Tag != Certificate {
		log.Fatalf("Response certificate of type %v", certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Tag)
	}

	certificate, _ := x509.ParseCertificate(certRepMessage.Response[0].CertifiedKeyPair.CertOrEncCert.Bytes)

	fmt.Printf("Certificate issued to %v\n", certificate.Subject)
	fmt.Printf("Certificate issued by %v\n", certificate.Issuer)
	fmt.Printf("Certificate valid from %v\n", certificate.NotBefore)
	fmt.Printf("Certificate valid until %v\n", certificate.NotAfter)

	certificatePublicKey := certificate.PublicKey

	if !reflect.DeepEqual(csrPublicKey, certificatePublicKey) {
		log.Fatalf("Certificate doesn't match to key provided in CSR")
	}


	certConfMessage := PKIMessage{
		Header: PKIHeader{
			PVNO:        CMP2000,
			Sender:      ChoiceConvert(senderDN, directoryName),
			Recipient:   ChoiceConvert(recipientDN, directoryName),
			MessageTime: time.Now(),
			ProtectionAlg: AlgorithmIdentifier{
				Algorithm: oidPBM,
				Parameters: PBMParameter{
					Salt: randomSalt,
					OWF: AlgorithmIdentifier{
						Algorithm:  oidSHA512,
						Parameters: []byte{},
					},
					IterationCount: 262144,
					MAC: AlgorithmIdentifier{
						Algorithm:  oidHMACWithSHA512,
						Parameters: []byte{},
					},
				},
			},
			SenderKID:     KeyIdentifier(senderDN.String()),
			RecipientKID:  KeyIdentifier(recipientDN.String()),
			TransactionID: randomTransactionID,
			SenderNonce:   randomSenderNonce,
			RecipNonce:    randomRecipNonce,
		},
		//Body: asn1.RawValue{Bytes: certificateRequest.Bytes, IsCompound: true, Class: asn1.ClassContextSpecific, Tag: PKCS10CertificationRequest},
	}

	certConfResponseBody := sendCMPMessage(certConfMessage, sharedSecret, url)

	var certConfResponseMessage PKIMessage
	asn1.Unmarshal(certConfResponseBody, &certConfResponseMessage)


	_ = certificatePublicKey

	_ = certificate

}

func sendCMPMessage(requestMessage PKIMessage, sharedSecret string, url string) (body []byte) {
	requestMessage.Protect(sharedSecret)

	pkiMessageAsDER, err1 := asn1.Marshal(requestMessage)
	if err1 != nil {
		log.Fatalf("Error marshaling structure 1:", err1)
	}

	fmt.Println(base64.StdEncoding.EncodeToString(pkiMessageAsDER))

	client := &http.Client{}

	resp, err := client.Post(url, "application/pkixcmp", bytes.NewReader(pkiMessageAsDER))
	if err != nil {
		log.Fatalf("Error:", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Fatalf("Status code %v doesn't equal 200", resp.Status)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body:", err)
	}

	return
}

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
