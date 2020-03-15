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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"testing"
)

func defaultTestKey() (*ecdsa.PrivateKey, []byte) {
	key, _ := crypto.HexToECDSA("2643eb22fec8c3d59b7f571eef9308202126d620b37f71f8a3345dc314d26a6d")
	b := crypto.FromECDSAPub(&key.PublicKey)
	return key, b
}

func TestNewEnvelope(t *testing.T) {
	content := "test"
	prv, pub := defaultTestKey()
	e, err := NewEnvelope([]byte(content), pub, DefaultDsa, DefaultCipher)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeToRLPBytes(prv)
	if err != nil {
		t.Fatal(err)
	}
	// recover
	re, err := DecodeFromRLPBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	rraw, err := re.EncodeToRLPBytes(prv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, rraw) {
		t.Fatalf("rlp not equal: \ngot: %x, \nwant: %x", rraw, raw)
	}
	plain, err := rlp.EncodeToBytes(re)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, plain) {
		t.Fatalf("rlp not equal: \ngot: %x, \nwant: %x", plain, raw)
	}
}

func TestEnvelope_Valid(t *testing.T) {
	content := "test"
	prv, pub := defaultTestKey()
	e, err := NewEnvelope([]byte(content), pub, DefaultDsa, DefaultCipher)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeToRLPBytes(prv)
	if err != nil {
		t.Fatal(err)
	}
	// recover
	re, err := DecodeFromRLPBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := re.Valid(); err != nil {
		t.Fatal(err)
	}

	re.Dsa = "te"
	if err := re.Valid(); err == nil {
		t.Fatal()
	}
}

func TestEnvelope_Sender(t *testing.T) {
	// marshal, before send
	content := "test"
	prv, pub := defaultTestKey()
	e, err := NewEnvelope([]byte(content), pub, DefaultDsa, DefaultCipher)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeToRLPBytes(prv)
	if err != nil {
		t.Fatal(err)
	}
	// recover, after receive
	re, err := DecodeFromRLPBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := re.Valid(); err != nil {
		t.Fatal(err)
	}

	sender, err := re.Sender()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, sender) {
		t.Fatalf("got wrong sender")
	}
}

func TestEnvelope_Decrypt(t *testing.T) {
	// marshal, before send
	content := []byte("test")
	prv, pub := defaultTestKey()
	e, err := NewEnvelope(content, pub, DefaultDsa, DefaultCipher)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.EncodeToRLPBytes(prv)
	if err != nil {
		t.Fatal(err)
	}
	// recover, after receive
	re, err := DecodeFromRLPBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := re.Valid(); err != nil {
		t.Fatal(err)
	}
	// decrypt
	plain, err := re.Decrypt(crypto.FromECDSA(prv))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, content) {
		t.Errorf("content not equal: \ngot: %v, \nwant: %v", plain, raw)
	}
	t.Logf("plain: %s", plain)
	t.Logf("\ne.mac:\n%x\nre.mac\n%x", e.Mac, re.Mac)
}
