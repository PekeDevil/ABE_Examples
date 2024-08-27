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

package main_LW11

import (
	"fmt"

	"github.com/fentec-project/gofe/abe"
)

// There can be less authorities, this is just an example
// In LW11 authorities must be created before running the setup
func SetupAuth_LW11() {
	maabe := abe.NewMAABE()
    // create five authorities. Each one handles 4 attributes
    atts1 := []string{"auth1:att1", "auth1:att2", "auth1:att3", "auth1:att4"}
    atts2 := []string{"auth2:att1", "auth2:att2", "auth2:att3", "auth2:att4"}
    atts3 := []string{"auth3:att1", "auth3:att2", "auth3:att3", "auth3:att4"}
	atts4 := []string{"auth4:att1", "auth4:att2", "auth4:att3", "auth4:att4"}
	atts5 := []string{"auth5:att1", "auth5:att2", "auth5:att3", "auth5:att4"}

    auth1, err:= maabe.NewMAABEAuth("auth1", atts1)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth1", err)
    }
    auth2, err:= maabe.NewMAABEAuth("auth2", atts2)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth2", err)
    }
    auth3, err:= maabe.NewMAABEAuth("auth3", atts3)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth3", err)
    }
	auth4, err:= maabe.NewMAABEAuth("auth4", atts4)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth4", err)
    }
	auth5, err:= maabe.NewMAABEAuth("auth5", atts5)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth5", err)
    }
    // The final MPK is composed of the MPK of each authority
	mpk := []*abe.MAABEPubKey{auth1.PubKeys(), auth2.PubKeys(), auth3.PubKeys(), auth4.PubKeys(), auth5.PubKeys()}
	_ = mpk
}

func SetupAuth_and_Encrypt_LW11() {
	maabe := abe.NewMAABE()
    // create five authorities. Each one handles 4 attributes
    atts1 := []string{"auth1:att1", "auth1:att2", "auth1:att3", "auth1:att4"}
    atts2 := []string{"auth2:att1", "auth2:att2", "auth2:att3", "auth2:att4"}
    atts3 := []string{"auth3:att1", "auth3:att2", "auth3:att3", "auth3:att4"}
	atts4 := []string{"auth4:att1", "auth4:att2", "auth4:att3", "auth4:att4"}
	atts5 := []string{"auth5:att1", "auth5:att2", "auth5:att3", "auth5:att4"}
    auth1, err:= maabe.NewMAABEAuth("auth1", atts1)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth1", err)
    }
    auth2, err:= maabe.NewMAABEAuth("auth2", atts2)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth2", err)
    }
    auth3, err:= maabe.NewMAABEAuth("auth3", atts3)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth3", err)
    }
	auth4, err:= maabe.NewMAABEAuth("auth4", atts4)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth4", err)
    }
	auth5, err:= maabe.NewMAABEAuth("auth5", atts5)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth5", err)
    }
    // The final MPK is composed of the MPK of each authority
	mpk := []*abe.MAABEPubKey{auth1.PubKeys(), auth2.PubKeys(), auth3.PubKeys(), auth4.PubKeys(), auth5.PubKeys()}

    // The policy also defines from which authority the attributes must come from
	policy_msp, err := abe.BooleanToMSP("(auth1:att1 AND auth1:att2 AND auth1:att3 AND auth1:att4 AND auth2:att1 AND auth2:att2 AND auth2:att3 AND auth2:att4 AND auth3:att1 AND auth3:att2 AND auth3:att3 AND auth3:att4 AND auth4:att1 AND auth4:att2 AND auth4:att3 AND auth4:att4 AND auth5:att1 AND auth5:att2 AND auth5:att3 AND auth5:att4)", false)
	if err != nil {
		fmt.Printf("Failed to generate the policy: %v", err)
	}
	msg := "hello world this is an important message,"
    ct, err := maabe.Encrypt(msg, policy_msp, mpk)
    if err != nil {
        fmt.Printf("Failed to encrypt: %v", err)
    }
	_ = ct
}

func SetupAuth_KeyGen_LW11() {
	maabe := abe.NewMAABE()
   // create three authorities, each with two attributes
    atts1 := []string{"auth1:att1", "auth1:att2", "auth1:att3", "auth1:att4"}
    atts2 := []string{"auth2:att1", "auth2:att2", "auth2:att3", "auth2:att4"}
    atts3 := []string{"auth3:att1", "auth3:att2", "auth3:att3", "auth3:att4"}
	atts4 := []string{"auth4:att1", "auth4:att2", "auth4:att3", "auth4:att4"}
	atts5 := []string{"auth5:att1", "auth5:att2", "auth5:att3", "auth5:att4"}
    auth1, err:= maabe.NewMAABEAuth("auth1", atts1)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth1", err)
    }
    auth2, err:= maabe.NewMAABEAuth("auth2", atts2)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth2", err)
    }
    auth3, err:= maabe.NewMAABEAuth("auth3", atts3)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth3", err)
    }
	auth4, err:= maabe.NewMAABEAuth("auth4", atts4)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth4", err)
    }
	auth5, err:= maabe.NewMAABEAuth("auth5", atts5)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth5", err)
    }
	mpk := []*abe.MAABEPubKey{auth1.PubKeys(), auth2.PubKeys(), auth3.PubKeys(), auth4.PubKeys(), auth5.PubKeys()}

    // choose a single user's Global ID
    gid := "bob"

    // authority 1 issues keys to user
    user_SK1, err := auth1.GenerateAttribKeys(gid, atts1)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }
    // each slice in user_SK1 contains the keys for one attribute
    // For example: user_SK1_att1, user_SK1_att2 := user_SK1[0], user_SK1[1]

    // authority 2 issues keys to user
    user_SK2, err := auth2.GenerateAttribKeys(gid, atts2)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }

    // authority 3 issues keys to user
    user_SK3, err := auth3.GenerateAttribKeys(gid, atts3)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }

    // authority 4 issues keys to user
    user_SK4, err := auth4.GenerateAttribKeys(gid, atts4)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }

    // authority 5 issues keys to user
    user_SK5, err := auth5.GenerateAttribKeys(gid, atts5)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }

	_ = user_SK1
	_ = user_SK2
	_ = user_SK3
	_ = user_SK4
	_ = user_SK5
	_ = mpk
}

func SetupAuth_and_Encrypt_and_KeyGen_and_decrypt_LW11() {
	maabe := abe.NewMAABE()
   // create three authorities, each with two attributes
    atts1 := []string{"auth1:att1", "auth1:att2", "auth1:att3", "auth1:att4"}
    atts2 := []string{"auth2:att1", "auth2:att2", "auth2:att3", "auth2:att4"}
    atts3 := []string{"auth3:att1", "auth3:att2", "auth3:att3", "auth3:att4"}
	atts4 := []string{"auth4:att1", "auth4:att2", "auth4:att3", "auth4:att4"}
	atts5 := []string{"auth5:att1", "auth5:att2", "auth5:att3", "auth5:att4"}
    auth1, err:= maabe.NewMAABEAuth("auth1", atts1)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth1", err)
    }
    auth2, err:= maabe.NewMAABEAuth("auth2", atts2)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth2", err)
    }
    auth3, err:= maabe.NewMAABEAuth("auth3", atts3)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth3", err)
    }
	auth4, err:= maabe.NewMAABEAuth("auth4", atts4)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth4", err)
    }
	auth5, err:= maabe.NewMAABEAuth("auth5", atts5)
    if err != nil {
        fmt.Printf("Failed generating authority %s: %v\n", "auth5", err)
    }
	mpk := []*abe.MAABEPubKey{auth1.PubKeys(), auth2.PubKeys(), auth3.PubKeys(), auth4.PubKeys(), auth5.PubKeys()}

    // choose a single user's Global ID
    gid := "bob"

    // authority 1 issues keys to user
    user_SK1, err := auth1.GenerateAttribKeys(gid, atts1)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }
    user_SK1_att1, user_SK1_att2, user_SK1_att3, user_SK1_att4:= user_SK1[0], user_SK1[1], user_SK1[2], user_SK1[3]

    // authority 2 issues keys to user
    user_SK2, err := auth2.GenerateAttribKeys(gid, atts2)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }
    user_SK2_att1, user_SK2_att2, user_SK2_att3, user_SK2_att4:= user_SK2[0], user_SK2[1], user_SK2[2], user_SK2[3]

    // authority 3 issues keys to user
    user_SK3, err := auth3.GenerateAttribKeys(gid, atts3)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }
    user_SK3_att1, user_SK3_att2, user_SK3_att3, user_SK3_att4 := user_SK3[0], user_SK3[1], user_SK3[2], user_SK3[3]

    // authority 4 issues keys to user
    user_SK4, err := auth4.GenerateAttribKeys(gid, atts4)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }
    user_SK4_att1, user_SK4_att2, user_SK4_att3, user_SK4_att4 := user_SK4[0], user_SK4[1], user_SK4[2], user_SK4[3]

	user_SK5, err := auth5.GenerateAttribKeys(gid, atts5)
    if err != nil {
        fmt.Printf("Failed to generate attribute keys: %v\n", err)
    }
    user_SK5_att1, user_SK5_att2, user_SK5_att3, user_SK5_att4:= user_SK5[0], user_SK5[1], user_SK5[2], user_SK5[3]
	
    // combining all the slices into one slice generates the user's secret key
    user_SK := []*abe.MAABEKey{user_SK1_att1, user_SK1_att2, user_SK1_att3, user_SK1_att4, user_SK2_att1, user_SK2_att2, user_SK2_att3, user_SK2_att4, user_SK3_att1, user_SK3_att2, user_SK3_att3, user_SK3_att4, user_SK4_att1, user_SK4_att2, user_SK4_att3, user_SK4_att4, user_SK5_att1, user_SK5_att2, user_SK5_att3, user_SK5_att4}

	policy_msp, err := abe.BooleanToMSP("(auth1:att1 AND auth1:att2 AND auth1:att3 AND auth1:att4 AND auth2:att1 AND auth2:att2 AND auth2:att3 AND auth2:att4 AND auth3:att1 AND auth3:att2 AND auth3:att3 AND auth3:att4 AND auth4:att1 AND auth4:att2 AND auth4:att3 AND auth4:att4 AND auth5:att1 AND auth5:att2 AND auth5:att3 AND auth5:att4)", false)
	if err != nil {
		fmt.Printf("Failed to generate the policy: %v", err)
	}
	msg := "hello world this is an important message,"
    ct, err := maabe.Encrypt(msg, policy_msp, mpk)
    if err != nil {
        fmt.Printf("Failed to encrypt: %v", err)
    }

	decrypted_msg, err := maabe.Decrypt(ct, user_SK)
    if err != nil {
        fmt.Printf("Error decrypting with selected keyset: %v\n", err)
    }
	_ = decrypted_msg
}
