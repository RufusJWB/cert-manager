package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"time"
)

var (
	oidCountry            = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
	oidCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidSerialNumber       = asn1.ObjectIdentifier{2, 5, 4, 5}
	oidLocality           = asn1.ObjectIdentifier{2, 5, 4, 7}
	oidProvince           = asn1.ObjectIdentifier{2, 5, 4, 8}
	oidStreetAddress      = asn1.ObjectIdentifier{2, 5, 4, 9}
	oidPostalCode         = asn1.ObjectIdentifier{2, 5, 4, 17}
)

var (
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSignatureRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSignatureDSAWithSHA256   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidPBM = asn1.ObjectIdentifier{1, 2, 840, 113533, 7, 66, 13}
)

/*
   PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
       -- text encoded as UTF-8 String [RFC3629] (note: each
       -- UTF8String MAY include an [RFC3066] language tag
       -- to indicate the language of the contained text
       -- see [RFC2482] for details)
*/

type PKIFreeText []string

type Name pkix.RDNSequence

func (name Name) String() (result string) {
	return pkix.RDNSequence(name).String()
}

func (name Name) GeneralName(contextSpecificTag int) (generalName asn1.RawValue) {

	var temp = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        contextSpecificTag,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(name)
			return b
		}(),
	}

	return temp
}

type IA5String string

func (ia5String IA5String) GeneralName(contextSpecificTag int) (generalName asn1.RawValue) {

	var temp = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        contextSpecificTag,
		IsCompound: true,
		Bytes: func() []byte {
			b, _ := asn1.Marshal(ia5String)
			return b
		}(),
	}

	return temp
}

type GeneralName asn1.RawValue

/*
GeneralName ::= CHOICE {
	otherName                       [0]     AnotherName,
	rfc822Name                      [1]     IA5String,
	dNSName                         [2]     IA5String,
	x400Address                     [3]     ORAddress,
	directoryName                   [4]     Name,
	ediPartyName                    [5]     EDIPartyName,
	uniformResourceIdentifier       [6]     IA5String,
	iPAddress                       [7]     OCTET STRING,
	registeredID                    [8]     OBJECT IDENTIFIER }
*/

const (
	otherName = iota
	rfc822Name
	dNSName
	x400Address
	directoryName
	ediPartyName
	uniformResourceIdentifier
	iPAddress
	registeredID
)

type KeyIdentifier []byte

/*
   PBMParameter ::= SEQUENCE {
       salt                OCTET STRING,
       -- note:  implementations MAY wish to limit acceptable sizes
       -- of this string to values appropriate for their environment
       -- in order to reduce the risk of denial-of-service attacks
       owf                 AlgorithmIdentifier,
       -- AlgId for a One-Way Function (SHA-1 recommended)
       iterationCount      INTEGER,
       -- number of times the OWF is applied
       -- note:  implementations MAY wish to limit acceptable sizes
       -- of this integer to values appropriate for their environment
       -- in order to reduce the risk of denial-of-service attacks
       mac                 AlgorithmIdentifier
       -- the MAC AlgId (e.g., DES-MAC, Triple-DES-MAC [PKCS11],
   }   -- or HMAC [RFC2104, RFC2202])
*/

type PBMParameter struct {
	Salt           []byte
	OWF            AlgorithmIdentifier
	IterationCount int
	MAC            AlgorithmIdentifier
}

/*
AlgorithmIdentifier  ::=  SEQUENCE  {
	algorithm               OBJECT IDENTIFIER,
	parameters              ANY DEFINED BY algorithm OPTIONAL  }
							   -- contains a value of the type
							   -- registered for use with the
							   -- algorithm object identifier value
*/

type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters any `asn1:"optional,omitempty"`
}

const (
	CMP1999 = iota
	CMP2000
	CMP2021
)

/*
PKIHeader ::= SEQUENCE {
         pvno                INTEGER     { cmp1999(1), cmp2000(2) },
         sender              GeneralName,
         -- identifies the sender
         recipient           GeneralName,
         -- identifies the intended recipient
         messageTime     [0] GeneralizedTime         OPTIONAL,
         -- time of production of this message (used when sender
         -- believes that the transport will be "suitable"; i.e.,
         -- that the time will still be meaningful upon receipt)
         protectionAlg   [1] AlgorithmIdentifier     OPTIONAL,
         -- algorithm used for calculation of protection bits
         senderKID       [2] KeyIdentifier           OPTIONAL,
         recipKID        [3] KeyIdentifier           OPTIONAL,
         -- to identify specific keys used for protection
         transactionID   [4] OCTET STRING            OPTIONAL,
         -- identifies the transaction; i.e., this will be the same in
         -- corresponding request, response, certConf, and PKIConf
         -- messages
         senderNonce     [5] OCTET STRING            OPTIONAL,
         recipNonce      [6] OCTET STRING            OPTIONAL,
         -- nonces used to provide replay protection, senderNonce
         -- is inserted by the creator of this message; recipNonce
         -- is a nonce previously inserted in a related message by
         -- the intended recipient of this message
         freeText        [7] PKIFreeText             OPTIONAL,
         -- this may be used to indicate context-specific instructions
         -- (this field is intended for human consumption)
         generalInfo     [8] SEQUENCE SIZE (1..MAX) OF
                                InfoTypeAndValue     OPTIONAL
         -- this may be used to convey context-specific information
         -- (this field not primarily intended for human consumption)
     }
*/

type PKIHeader struct {
	PVNO          int
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	MessageTime   time.Time           `asn1:"generalized,explicit,optional,tag:0,omitempty"`
	ProtectionAlg AlgorithmIdentifier `asn1:"explicit,optional,tag:1,omitempty"`
	SenderKID     KeyIdentifier       `asn1:"explicit,optional,tag:2,omitempty"`
	RecipientKID  KeyIdentifier       `asn1:"explicit,optional,tag:3,omitempty"`
	TransactionID []byte              `asn1:"explicit,optional,tag:4,omitempty"`
	SenderNonce   []byte              `asn1:"explicit,optional,tag:5,omitempty"`
	RecipNonce    []byte              `asn1:"explicit,optional,tag:6,omitempty"`
	// FreeText      PKIFreeText         `asn1:"explicit,optional,tag:7,omitempty"` // Not working
	// GeneralInfo   []pkix.AttributeTypeAndValue `asn1:"explicit,optional,tag:8,omitempty"` // Not working
}

type PKIBody any

type PKIProtection asn1.BitString

type CMPCertificate any

/*
      PKIMessage ::= SEQUENCE {
         header           PKIHeader,
         body             PKIBody,
         protection   [0] PKIProtection OPTIONAL,
         extraCerts   [1] SEQUENCE SIZE (1..MAX) OF CMPCertificate
                          OPTIONAL
	  }
*/

type PKIMessage struct {
	Header     PKIHeader
	Body       PKIBody
	Protection PKIProtection    `asn1:"optional,tag:0,omitempty, explicit"`
	ExtraCerts []CMPCertificate `asn1:"optional,tag:1,omitempty, explicit"`
}
