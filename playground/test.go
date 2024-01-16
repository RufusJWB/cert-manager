package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"time"
)

type Type1 struct {
	ID    int
	Value []byte
}

type Type2 struct {
	ID    int
	Value string
}

type MyStructure struct {
	ID     int
	Choice asn1.RawValue
}

func main() {

	country := "DE"
	organization := "Siemens"
	commonName := "www.siemens.com"

	/*
		senderAsName := Name{[]pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: country},},
			[]pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: organization},},
			[]pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName}}}

		senderAsGeneralName := senderAsName.GeneralName(4);
	*/

	testStruct := PKIMessage{
		Header: PKIHeader{
			PVNO: PVNO,
			Sender: (Name{[]pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: country}},
				[]pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: organization}},
				[]pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName}}}).GeneralName(4),
			Recipient: (Name{[]pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: country}},
				[]pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: organization}},
				[]pkix.AttributeTypeAndValue{
					{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: commonName}}}).GeneralName(4),
			MessageTime: time.Now(),
			ProtectionAlg: pkix.AlgorithmIdentifier{
				Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}, // --> https://github.com/zjj/golibkit/blob/main/certutil/helper.go
				Parameters: asn1.NullRawValue,
			},
			SendKID:  []byte{},
			RecipKID: []byte{},
		},
		Body:       []int{},
		Protection: PKIProtection{},
		ExtraCerts: []CMPCertificate{},
	}

	bytes1, err1 := asn1.Marshal(testStruct)
	if err1 != nil {
		fmt.Println("Error marshaling structure 1:", err1)
		return
	}

	base64Str1 := base64.StdEncoding.EncodeToString(bytes1)
	fmt.Println(base64Str1)
	//fmt.Println(base64Str2)

	// Decode from base64
	//decodedBytes1, _ := base64.StdEncoding.DecodeString(base64Str1)
	//decodedBytes2, _ := base64.StdEncoding.DecodeString(base64Str2)

	/*
		// Unmarshal from ASN.1 DER
		var unmarshaledStruct1, unmarshaledStruct2 MyStructure
		_, err3 := asn1.Unmarshal(decodedBytes1, &unmarshaledStruct1)


		// Unmarshal the choice based on the tag
		switch unmarshaledStruct1.Choice.Tag {
		case 0:
			var choice1 Type1
			_, err := asn1.Unmarshal(unmarshaledStruct1.Choice.Bytes, &choice1)
			if err != nil {
				fmt.Println("Error unmarshaling choice1:", err)
				return
			}
			fmt.Println(choice1)
		case 1:
			var choice2 Type2
			_, err := asn1.Unmarshal(unmarshaledStruct1.Choice.Bytes, &choice2)
			if err != nil {
				fmt.Println("Error unmarshaling choice2:", err)
				return
			}
			fmt.Println(choice2)
		}

		// Unmarshal the choice based on the tag
		switch unmarshaledStruct2.Choice.Tag {
		case 0:
			var choice1 Type1
			_, err := asn1.Unmarshal(unmarshaledStruct2.Choice.Bytes, &choice1)
			if err != nil {
				fmt.Println("Error unmarshaling choice1:", err)
				return
			}
			fmt.Println(choice1)
		case 1:
			var choice2 Type2
			_, err := asn1.Unmarshal(unmarshaledStruct2.Choice.Bytes, &choice2)
			if err != nil {
				fmt.Println("Error unmarshaling choice2:", err)
				return
			}
			fmt.Println(choice2)
	*/
}
