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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pip1998/secretly-lib/pkg/envelope"
)

type Envelope struct {
	Dsa     string // digital signature algorithm
	Cipher  string // symmetric-key algorithm
	payload []byte // plain content
	sender  []byte // sender public key

	env *envelope.Envelope
}

func NewEnvelope(content, receiver []byte) (*Envelope, error) {
	e := Envelope{
		Dsa:     envelope.DefaultDsa,
		Cipher:  envelope.DefaultCipher,
		payload: content,
	}
	var err error
	e.env, err = envelope.NewEnvelope(content, receiver, e.Dsa, e.Cipher)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

//EncodeToRLPBytes marshal an Envelope to raw with signature
func (e *Envelope) EncodeToRLPBytes(prv []byte) ([]byte, error) {
	ecdsaPrv, err := crypto.ToECDSA(prv)
	if err != nil {
		return nil, err
	}
	return e.env.EncodeToRLPBytes(ecdsaPrv)
}

//DecodeFromRLPBytes unmarshal raw to an Envelope
func DecodeFromRLPBytes(raw []byte) (*Envelope, error) {
	env, err := envelope.DecodeFromRLPBytes(raw)
	if err != nil {
		return nil, err
	}
	e := &Envelope{
		Dsa:    envelope.DefaultDsa,
		Cipher: envelope.DefaultCipher,
	}
	err = env.Valid()
	if err != nil {
		return nil, err
	}
	e.env = env
	return e, nil
}

//Decrypt decrypt envelope with your private key
func (e *Envelope) Decrypt(prv []byte) ([]byte, error) {
	if e.payload != nil {
		return e.payload, nil
	}
	plain, err := e.env.Decrypt(prv)
	if err != nil {
		return nil, err
	}
	e.payload = plain
	return e.payload, nil
}

//Sender sender of the envelope
func (e *Envelope) Sender() ([]byte, error) {
	if e.sender != nil {
		return e.sender, nil
	}
	sender, err := e.env.Sender()
	if err != nil {
		return nil, err
	}
	e.sender = sender
	return e.sender, nil
}
