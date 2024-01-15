package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

type Name pkix.RDNSequence

func (name Name) GeneralName() (generalName GeneralName, err error) {

	var outerErr error

	var temp = GeneralName{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes: func() []byte {
			b, err := asn1.Marshal(name)
			outerErr = err
			return b
		}(),
	}

	return temp, outerErr
}

type IA5String string

func (ia5String IA5String) GeneralName(tag int) (generalName GeneralName, err error) {

	var outerErr error

	var temp = GeneralName{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes: func() []byte {
			b, err := asn1.Marshal(ia5String)
			outerErr = err
			return b
		}(),
	}

	return temp, outerErr
}

type GeneralName asn1.RawValue

type PKIHeader struct {
	PVNO          int
	Sender        GeneralName
	Recipient     GeneralName
	MessageTime   time.Time                `asn1:"generalized,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"optional,tag:1,omitempty"`
	//SendKID       any                          `asn1:"optional,tag:2,omitempty"`
	//RecipKID      any                          `asn1:"optional,tag:3,omitempty"`
	//TransactionID []byte                       `asn1:"optional,tag:4,omitempty"`
	//SenderNonce   []byte                       `asn1:"optional,tag:5,omitempty"`
	//RecipNonce    []byte                       `asn1:"optional,tag:6,omitempty"`
	//FreeText      PKIFreeText                  `asn1:"optional,tag:7,omitempty"`
	//GeneralInfo   []pkix.AttributeTypeAndValue `asn1:"optional,tag:8,omitempty"`
}

type PKIBody asn1.RawValue


type PKIProtection asn1.BitString

type CMPCertificate struct{}

type PKIMessage struct {
	Header     PKIHeader
	Body       PKIBody
	Protection PKIProtection    `asn1:"optional,tag:0,omitempty"`
	ExtraCerts []CMPCertificate `asn1:"optional,tag:1,omitempty"`
}
