// Copyright (C) 2020  chaoyongzhang
// This file is part of the secretly-lib
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package envelope

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	crypto2 "github.com/pip1998/secretly-lib/pkg/crypto"
	mrand "math/rand"
	"time"
)

const (
	DefaultVersion = 1
	DefaultCipher  = "aes-128-ctr"
	DefaultDsa     = "secp256k1"
)

func init() {
	mrand.Seed(time.Now().UnixNano())
}

type Envelope struct {
	Version byte   // current version
	Dsa     string // digital signature algorithm
	Cipher  string // symmetric-key algorithm
	Payload []byte // symmetric encryped content
	Mac     []byte // mac to verify decrypted plain content
	Key     []byte // public key encryped symmetric-key
	Iv      []byte // iv of cipher
	Sig     []byte // signature signed by sender with field above
}

//NewEnvelope create an envelope, with content and public key of receiver
func NewEnvelope(content, pub []byte, dsa, cipher string) (e *Envelope, err error) {
	e = &Envelope{
		Version: DefaultVersion,
		Dsa:     dsa,
		Cipher:  cipher,
	}

	symmetricKey := make([]byte, 16)
	iv := make([]byte, 16)
	mrand.Read(symmetricKey)
	mrand.Read(iv)
	e.Iv = iv
	e.Payload, err = crypto2.AesCTRXOR(symmetricKey, content, e.Iv)
	if err != nil {
		return
	}
	e.Key, err = crypto2.Encrypt(pub, symmetricKey)
	e.Mac = mac(content, symmetricKey)
	return
}

//EncodeToRLPBytes marshal an Envelope to raw with signature
func (e *Envelope) EncodeToRLPBytes(prv *ecdsa.PrivateKey) ([]byte, error) {
	hash := e.Hash()
	log.Debug("EncodeToRLPBytes", "hash", fmt.Sprintf("%x", hash))
	if prv != nil {
		sig, err := crypto.Sign(hash.Bytes(), prv)
		if err != nil {
			return nil, err
		}
		log.Debug("EncodeToRLPBytes", "sig", fmt.Sprintf("%x", sig))
		e.Sig = sig
	}
	return rlp.EncodeToBytes(e)
}

//DecodeFromRLPBytes unmarshal raw to an Envelope
func DecodeFromRLPBytes(raw []byte) (*Envelope, error) {
	e := &Envelope{}
	err := rlp.DecodeBytes(raw, e)
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Valid verify this envelope
func (e *Envelope) Valid() error {
	if e.Version != DefaultVersion {
		return fmt.Errorf("version not match. got(%d) want(%d)", e.Version, DefaultVersion)
	}

	if e.Dsa != DefaultDsa {
		return fmt.Errorf("dsa not supported. got(%s)", e.Dsa)
	}

	if e.Cipher != DefaultCipher {
		return fmt.Errorf("cipher not supported. got(%s)", e.Cipher)
	}

	// verify signature
	if !e.verifySig() {
		return fmt.Errorf("sig not match")
	}
	return nil
}

//Sender sender of the envelope
func (e *Envelope) Sender() ([]byte, error) {
	sig := e.Sig
	if sig == nil || len(sig) != crypto.SignatureLength {
		return nil, fmt.Errorf("signature not valid %x", sig)
	}
	sighash := e.Hash()
	// recover the public key from the signature
	return crypto.Ecrecover(sighash[:], sig)
}

//Decrypt decrypt envelope with your private key
func (e *Envelope) Decrypt(prv []byte) ([]byte, error) {
	symmetricKey, err := crypto2.Decrypt(prv, e.Key)
	if err != nil {
		return nil, err
	}
	plain, err := crypto2.AesCTRXOR(symmetricKey, e.Payload, e.Iv)
	if err != nil {
		return nil, err
	}
	mac := mac(plain, symmetricKey)
	if !bytes.Equal(mac, e.Mac) {
		return nil, errors.New("decrypt fail, mac not match")
	}
	return plain, nil
}

func mac(content, symmetricKey []byte) []byte {
	hash := crypto.Keccak256Hash(content, symmetricKey)
	return hash[:]
}
func (e *Envelope) verifySig() bool {
	sig := e.Sig
	if sig == nil || len(sig) != crypto.SignatureLength {
		log.Debug("Payload_VerifySig", "err", fmt.Errorf("signature not valid %x", sig))
		return false
	}
	sighash := e.Hash()
	// recover the public key from the signature
	pub, err := crypto.Ecrecover(sighash[:], sig)
	if err != nil {
		log.Debug("Payload_VerifySig", "err", err)
		return false
	}
	if len(pub) == 0 || pub[0] != 4 {
		return false
	}
	log.Debug("Envelope_VerifySig", "pub", fmt.Sprintf("%x", pub))
	log.Debug("Envelope_VerifySig", "hash", fmt.Sprintf("%x", sighash[:]))
	log.Debug("Envelope_VerifySig", "sig", fmt.Sprintf("%x", sig))
	// verify signature
	return crypto.VerifySignature(pub, sighash[:], sig[:64])
}

func (e *Envelope) rlpContent() ([]byte, error) {
	return rlp.EncodeToBytes([]interface{}{
		e.Version,
		e.Dsa,
		e.Cipher,
		e.Payload,
		e.Key,
		e.Iv,
		e.Mac,
	})
}

// Hash returns the hash of the content of Envelope
func (e *Envelope) Hash() common.Hash {
	encoded, _ := e.rlpContent()
	hash := crypto.Keccak256Hash(encoded)
	return hash
}
