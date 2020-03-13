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

import "github.com/pip1998/secretly-lib/pkg/crypto"

//EncryptEcies encrypt with ecies func
func EncryptEcies(pub, value []byte) ([]byte, error) {
	return crypto.Encrypt(pub, value)
}

//DecryptEcies decrypt with ecies func
func DecryptEcies(prv, value []byte) ([]byte, error) {
	return crypto.Decrypt(prv, value)
}
