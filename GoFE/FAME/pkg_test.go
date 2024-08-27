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
	"testing"
) 


func BenchmarkSetup (b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup_FAME ()
	}
}

func BenchmarkSetup_and_Encrypt (b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup_and_Encrypt_FAME ()
	}
}

func BenchmarkSetup_KeyGen (b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup_KeyGen_FAME ()
	}
}

func BenchmarkSetup_and_Encrypt_and_KeyGen_and_decrypt (b *testing.B) {
	for i := 0; i < b.N; i++ {
		Setup_and_Encrypt_and_KeyGen_and_decrypt_FAME ()
	}	
}
