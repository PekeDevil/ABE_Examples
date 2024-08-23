################################################################################
###################### Hybrid Encryption EXAMPLE ###############################
# DESCRIPTION: This example demonstrates the Hybrid CP-ABE scheme.
# Based on:
# https://github.com/JHUISI/charm/blob/dev/charm/adapters/abenc_adapt_hybrid.py
################################################################################
################################################################################


# Required imports from the library:
from charm.toolbox.ABEnc import HybridABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07

# Required import to take time measurements:
import timeit

def main():
    # instantiate a bilinear pairing map
    groupObj = PairingGroup('SS512') # BSW07 only works with pairing groups.
    cpabe = CPabe_BSW07(groupObj)
    hyb_abe = HybridABEnc(cpabe, groupObj)

    # run the set up
    (pk, msk) = hyb_abe.setup()
   
    # run the key generation. attr_list can contain as many attributes as desired. However, more attributes require more time.
    attr_list = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']        
    key_abe = hyb_abe.keygen(pk, msk, attr_list)

    # run the encryption
    policy_str = '(ONE and TWO and THREE and FOUR and FIVE and SIX and SEVEN and EIGHT and NINE and TEN)'
    CT = hyb_abe.encrypt(pk, msg, policy_str)

    #run decryption
    PT = hyb_abe.decrypt(pk, key_abe, CT)


    # run the ABE encryption. policy_str can contain as many attributes as desired.
    # In this scheme, ABE is used to encrypt a the symmetric key that will later be used to encrypt the actual message.
    key_sym_seed = groupObj.random(GT)
    policy_str = '(ONE and TWO and THREE and FOUR and FIVE and SIX and SEVEN and EIGHT and NINE and TEN)'
    CTabe = cpabe.encrypt(pk, key_sym_seed, policy_str) #encryption

    #run the symmetric encryption
    msg = b"hello world this is an important message."   
    cipher_enc = AuthenticatedCryptoAbstraction(sha2(key_sym_seed)) #AES instantiation with key_sym_seed
    CTaes = cipher_enc.encrypt(msg) # AES message encryption

    #check everything went ok
    print ("Original message to be encrypted: ", msg)
    print ("Decrypted message: ", PT)

if __name__ == "__main__":
    debug = True
    main()