package main

import (
    "encoding/asn1"
    "encoding/base64"
    "fmt"
)

type Type1 struct {
    ID int
    Value []byte
}

type Type2 struct {
    ID int
    Value []byte
}

type MyStructure struct {
    ID int
    Choice asn1.RawValue
}

func main() {
    // Create a structure with a Type1 choice
    myStruct1 := MyStructure{
        ID: 1,
        Choice: asn1.RawValue{
            Class: asn1.ClassContextSpecific,
            Tag: 0,
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
            Class: asn1.ClassContextSpecific,
            Tag: 1,
            IsCompound: true,
            Bytes: func() []byte {
                b, _ := asn1.Marshal(Type2{ID: 43, Value: []byte("Hello, ASN.1!")})
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
}
