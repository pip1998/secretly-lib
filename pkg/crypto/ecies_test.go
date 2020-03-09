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
	"github.com/ethereum/go-ethereum/crypto"
	"testing"
)

var msg = "test"

func TestEncrypt(t *testing.T) {
	prv0, _ := crypto.GenerateKey()
	pub0 := &prv0.PublicKey
	prv1, _ := crypto.GenerateKey()
	//pub1 := &prv1.PublicKey

	prvBytes0 := crypto.FromECDSA(prv0)
	pubBytes0 := crypto.FromECDSAPub(pub0)

	prvBytes1 := crypto.FromECDSA(prv1)

	//ENCRYPT
	value, err := Encrypt(pubBytes0, []byte(msg))
	if err != nil {
		t.Fatal("encrypt err: ", err)
	}
	t.Logf("value: %x\n", value)

	//DECRYPT
	result, err := Decrypt(prvBytes0, value)
	if err != nil {
		t.Fatal("decrypt err: ", err)
	}

	t.Logf("result: %s\n", result)
	if string(result) != msg {
		t.Fatal("decrypt wrong")
	}

	//DECRYPT WITH WRONG KEY
	result, err = Decrypt(prvBytes1, value)
	if err == nil {
		t.Fatal("decrypt wrong err: ", err)
	}

	t.Logf("result: %s\n", result)
	if string(result) == msg {
		t.Fatal("decrypt wrong wrong")
	}
}
