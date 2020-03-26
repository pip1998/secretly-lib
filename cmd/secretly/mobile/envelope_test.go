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

package mobile

import (
	"bytes"
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

func defaultSenderKey() ([]byte, []byte) {
	key, _ := crypto.HexToECDSA("2643eb22fec8c3d59b7f571eef9308202126d620b37f71f8a3345dc314d26a6d")
	b := crypto.FromECDSAPub(&key.PublicKey)
	return crypto.FromECDSA(key), b
}

func defaultReceiverKey() ([]byte, []byte) {
	key, _ := crypto.HexToECDSA("5c114104e312d671c9737ef842eccb51c802eb052f400e8e6690a8388a8b0c0e")
	b := crypto.FromECDSAPub(&key.PublicKey)
	return crypto.FromECDSA(key), b
}

func TestEnvelopeTransport(t *testing.T) {
	// create an envelope
	content := []byte("test")
	prvSender, sender := defaultSenderKey()
	prvReceiver, receiver := defaultReceiverKey()
	e, err := NewEnvelope(content, receiver)
	if err != nil {
		t.Fatal(err)
	}
	// marshal it (when send)
	raw, err := e.EncodeToRLPBytes(prvSender)
	if err != nil {
		t.Fatal(err)
	}
	// unmarshal it (when receive)
	re, err := DecodeFromRLPBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	// get sender
	reSender, err := re.Sender()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reSender, sender) {
		t.Fatalf("sender not equal: \ngot: %x, \nwant: %x", reSender, sender)

	}
	// get plain content
	plain, err := re.Decrypt(prvReceiver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, plain) {
		t.Fatalf("content not equal: \ngot: %x, \nwant: %x", plain, content)
	}
}
