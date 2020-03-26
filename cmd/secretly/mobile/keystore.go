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
	"encoding/hex"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pborman/uuid"
	"io/ioutil"
	"os"
	"path/filepath"
)

var pwds map[string]string

func init() {
	pwds = make(map[string]string)
}

func GenerateKey(passphrase, keyfilepath string) error {
	// If not loaded, generate random.
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		utils.Fatalf("Failed to generate random private key: %v", err)
	}

	// Create the keyfile object with a random UUID.
	id := uuid.NewRandom()
	key := &keystore.Key{
		Id:         id,
		Address:    crypto.PubkeyToAddress(privateKey.PublicKey),
		PrivateKey: privateKey,
	}

	// Encrypt key with passphrase.
	keyjson, err := keystore.EncryptKey(key, passphrase, keystore.StandardScryptN, keystore.StandardScryptP)
	if err != nil {
		utils.Fatalf("Error encrypting key: %v", err)
	}

	// Store the file to disk.
	if err := os.MkdirAll(filepath.Dir(keyfilepath), 0700); err != nil {
		utils.Fatalf("Could not create directory %s", filepath.Dir(keyfilepath))
		return err
	}
	if err := ioutil.WriteFile(keyfilepath, keyjson, 0600); err != nil {
		utils.Fatalf("Failed to write keyfile to %s: %v", keyfilepath, err)
		return err
	}
	pwds[keyfilepath] = passphrase
	return nil
}

func GetKey(passphrase, file string) (*PlainKey, error) {
	keyjson, err := ioutil.ReadFile(file)
	if err != nil {
		utils.Fatalf("Failed to read keyfile %s", err)
		return nil, err
	}
	// Decrypt with the correct password
	key, err := keystore.DecryptKey(keyjson, passphrase)
	if err != nil {
		utils.Fatalf("json key failed to decrypt: %v", err)
	}
	pwds[file] = passphrase
	privateKey := key.PrivateKey
	privHex := hex.EncodeToString(crypto.FromECDSA(privateKey))
	pubHex := hex.EncodeToString(crypto.FromECDSAPub(&privateKey.PublicKey))
	return &PlainKey{PublicKey: pubHex, PrivateKey: privHex}, nil
}
