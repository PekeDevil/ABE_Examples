/*
 * Copyright (c) 2018 XLAB d.o.o
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"fmt"

	"github.com/fentec-project/gofe/abe"
) 

func Setup_FAME () {
	my_FAME := abe.NewFAME()
	pubKey, secKey, err := my_FAME.GenerateMasterKeys()
	if err != nil {
		fmt.Printf("Failed to generate master keys: %v", err)
	}
	_ = pubKey
	_ = secKey
}

// run the ABE encryption. The policy can contain as many attributes as desired.
// AND policies are always more time-consuming than OR policies. More attributes also mean more time.
// The policy is defined in a MSP structure.
func Setup_and_Encrypt_FAME () {	
	my_FAME := abe.NewFAME()
	pubKey, secKey, err := my_FAME.GenerateMasterKeys()
	if err != nil {
		fmt.Printf("Failed to generate master keys: %v", err)
	}
	policy_msp, err := abe.BooleanToMSP("(1 AND 2 AND 3 AND 4 AND 5 AND 6 AND 7 AND 8 AND 9 AND 10)", false)
	msg := "hello world this is an important message,"
	if err != nil {
		fmt.Printf("Failed to generate the policy: %v", err)
	}
	cipher, err := my_FAME.Encrypt(msg, policy_msp, pubKey)
	if err != nil {
		fmt.Printf("Failed to encrypt: %v", err)
	}
	_ = cipher
	_ = secKey
}

func Setup_KeyGen_FAME () {
	my_FAME := abe.NewFAME()
	pubKey, secKey, err := my_FAME.GenerateMasterKeys()		
	if err != nil {
		fmt.Printf("Failed to generate master keys: %v", err)
	}
	user_att := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	keys, err := my_FAME.GenerateAttribKeys(user_att, secKey)
	if err != nil {
		fmt.Printf("Failed to generate keys: %v", err)
	}
	_ = keys
	_ = pubKey
}

func Setup_and_Encrypt_and_KeyGen_and_decrypt_FAME () {
	my_FAME := abe.NewFAME()
	pubKey, secKey, err := my_FAME.GenerateMasterKeys()
	if err != nil {
		fmt.Printf("Failed to generate master keys: %v", err)
	}
	policy_msp, err := abe.BooleanToMSP("(1 AND 2 AND 3 AND 4 AND 5 AND 6 AND 7 AND 8 AND 9 AND 10)", false)
	msg := "hello world this is an important message,"
	if err != nil {
		fmt.Printf("Failed to generate the policy: %v", err)
	}
	cipher, err := my_FAME.Encrypt(msg, policy_msp, pubKey)
	if err != nil {
		fmt.Printf("Failed to encrypt: %v", err)
	}
	user_att := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	keys, err := my_FAME.GenerateAttribKeys(user_att, secKey)
	if err != nil {
		fmt.Printf("Failed to generate keys: %v", err)
	}
	decrypted_msg, err := my_FAME.Decrypt(cipher, keys, pubKey)
	_ = decrypted_msg
}