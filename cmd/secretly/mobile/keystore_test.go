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
	"os"
	"testing"
)

const (
	key  = ""
	file = "/tmp/key.json"
)

func TestGenerateKey(t *testing.T) {
	if _, err := os.Stat(file); err == nil {
		err := os.Remove(file)
		if err != nil {
			t.Fatal(err)
		}
	}
	err := GenerateKey(key, file)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := GetKey(key, file)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(plain.PrivateKey, plain.PublicKey)
}
