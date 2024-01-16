package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

const PVNO = 2

type Name pkix.RDNSequence

func (name Name) GeneralName(tag int) (generalName asn1.RawValue) {

	var temp = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(name)
			return b
		}(),
	}

	return temp
}

type IA5String string

func (ia5String IA5String) GeneralName(tag int) (generalName asn1.RawValue) {

	var temp = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(ia5String)
			return b
		}(),
	}

	return temp
}

type GeneralName asn1.RawValue

type KeyIdentifier []byte

type PKIHeader struct {
	PVNO          int
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	MessageTime   time.Time                `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	SendKID       KeyIdentifier            `asn1:"optional,tag:2,omitempty"`
	RecipKID      KeyIdentifier            `asn1:"optional,tag:3,omitempty"`
	//TransactionID []byte                       `asn1:"optional,tag:4,omitempty"`
	//SenderNonce   []byte                       `asn1:"optional,tag:5,omitempty"`
	//RecipNonce    []byte                       `asn1:"optional,tag:6,omitempty"`
	//FreeText      PKIFreeText                  `asn1:"optional,tag:7,omitempty"`
	//GeneralInfo   []pkix.AttributeTypeAndValue `asn1:"optional,tag:8,omitempty"`
}

type PKIBody any

type PKIProtection asn1.BitString

type CMPCertificate any

type PKIMessage struct {
	Header     PKIHeader
	Body       PKIBody
	Protection PKIProtection    `asn1:"optional,tag:0,omitempty"`
	ExtraCerts []CMPCertificate `asn1:"optional,tag:1,omitempty"`
}
