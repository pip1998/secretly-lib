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
	"bytes"
	mrand "math/rand"
	"testing"
	"time"
)

func TestAesCTRXOR(t *testing.T) {
	mrand.Seed(time.Now().UnixNano())
	msg := "test"
	// prepare
	key := make([]byte, 16)
	iv := make([]byte, 16)
	mrand.Read(key)
	mrand.Read(iv)
	t.Logf("\nkey: %x\niv : %x", key, iv)
	// encrypt
	enmsg, err := AesCTRXOR(key, []byte(msg), iv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("encrypted msg: %x", enmsg)

	// decrypt
	_, _ = AesCTRXOR(key, enmsg, iv)
	t.Logf("encrypted msg: %x", enmsg)
	demsg, err := AesCTRXOR(key, enmsg, iv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(demsg, []byte(msg)) {
		t.Errorf("decrypted not match")
	}
	t.Logf("decrypted msg: %s", demsg)
}
