package main

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
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
	// Create a structure with a Type1 choice
	myStruct1 := MyStructure{
		ID: 1,
		Choice: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes: func() []byte {
				b, _ := asn1.Marshal(Type1{ID: 42, Value: []byte("Hello, world!")})
				return b
			}(),
		},
	}

	// Create a structure with a Type2 choice
	myStruct2 := MyStructure{
		ID: 2,
		Choice: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
			Bytes: func() []byte {
				b, _ := asn1.Marshal(Type2{ID: 43, Value: "Hello, ASN.1!"})
				return b
			}(),
		},
	}

	// Marshal to ASN.1 DER
	bytes1, err1 := asn1.Marshal(myStruct1)
	if err1 != nil {
		fmt.Println("Error marshaling structure 1:", err1)
		return
	}

	bytes2, err2 := asn1.Marshal(myStruct2)
	if err2 != nil {
		fmt.Println("Error marshaling structure 2:", err2)
		return
	}

	// Encode to base64
	base64Str1 := base64.StdEncoding.EncodeToString(bytes1)
	base64Str2 := base64.StdEncoding.EncodeToString(bytes2)

	fmt.Println(base64Str1)
	fmt.Println(base64Str2)

	// Decode from base64
	decodedBytes1, _ := base64.StdEncoding.DecodeString(base64Str1)
	decodedBytes2, _ := base64.StdEncoding.DecodeString(base64Str2)

	// Unmarshal from ASN.1 DER
	var unmarshaledStruct1, unmarshaledStruct2 MyStructure
	_, err3 := asn1.Unmarshal(decodedBytes1, &unmarshaledStruct1)
	_, err4 := asn1.Unmarshal(decodedBytes2, &unmarshaledStruct2)
	if err3 != nil || err4 != nil {
		fmt.Println("Error unmarshaling structures:", err3, err4)
		return
	}

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
	}
}
