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

package crypto

import (
	"crypto/rand"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
)

//Cryptor cryptor interface
type Cryptor interface {
	DecryptEcies(value []byte) []byte
	EncryptEcies(to string, value []byte) []byte
}

//Encrypt
func Encrypt(pub, value []byte) ([]byte, error) {

	ecdsaPub, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		return nil, fmt.Errorf("importPublicKey: error: %v", err)
	}
	pubKey := ecies.ImportECDSAPublic(ecdsaPub)
	return ecies.Encrypt(rand.Reader, pubKey, value, nil, nil)
}

//Decrypt
func Decrypt(prv, value []byte) ([]byte, error) {
	ecdsaPrv, err := crypto.ToECDSA(prv)
	if err != nil {
		return nil, err
	}
	pri := ecies.ImportECDSA(ecdsaPrv)
	return pri.Decrypt(value, nil, nil)
}
