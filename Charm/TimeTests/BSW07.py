# Required imports from the library:
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.math.pairing import hashPair as sha2

# Required import to take time measurements:
import timeit

def main():
    # instantiate a bilinear pairing map
    groupObj = PairingGroup('SS512')
    cpabe = CPabe_BSW07(groupObj)

    # run the set up
    def my_setup ():
        (pk, msk) = cpabe.setup()
    # Measure the time taken to run the setup. We run the function 500 times and get the total time required. 
    time_setup= (timeit.timeit(setup = "gc.enable()",
                     stmt = my_setup,
                     number = 500))
    # It is then divided by 500 again to get the mean time for each execution
    time_setup_iter= time_setup/500
    print ("Mean time per iteration for setup [s] ->", time_setup_iter)

    
    # run the key generation. attr_list can contain as many attributes as desired. However, more attributes require more time.
    def my_keygen ():
        (pk, msk) = cpabe.setup()
        attr_list = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']        
        key_abe = cpabe.keygen(pk, msk, attr_list)
    # Measure the time taken to run keygen
    time_setup_keygen = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_keygen,
                     number = 500))
    time_setup_keygen_iter= time_setup_keygen/500
    time_keygen_iter = time_setup_keygen_iter - time_setup_iter
    print ("Mean time per iteration for keygen [s] ->", time_keygen_iter)


    # run the ABE encryption. policy_str can contain as many attributes as desired.
    # AND policies are always more time-consuming than OR policies. More attributes also mean more time.
    # In this scheme, ABE is used to encrypt a the symmetric key that will later be used to encrypt the actual message.
    def my_ABE_Enc ():
        (pk, msk) = cpabe.setup()
        key_sym_seed = groupObj.random(GT)
        policy_str = '(ONE and TWO and THREE and FOUR and FIVE and SIX and SEVEN and EIGHT and NINE and TEN)'
        CTabe = cpabe.encrypt(pk, key_sym_seed, policy_str) #encryption
        
    # Measure the time taken to run ABE encryption    
    time_setup_ABE_Enc_iter = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_ABE_Enc,
                     number = 500))/500
    time_ABE_Enc_iter = time_setup_ABE_Enc_iter - time_setup_iter
    print ("Mean time per iteration for ABE encryption [s] ->", time_ABE_Enc_iter)


    # run the ABE encryption. policy_str can contain as many attributes as desired.
    # AND policies are always more time-consuming than OR policies. More attributes also mean more time.   
    def my_ABE_Dec ():
        (pk, msk) = cpabe.setup()
        attr_list = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']        
        key_abe = cpabe.keygen(pk, msk, attr_list)
        key_sym_seed = groupObj.random(GT)
        policy_str = '(ONE and TWO and THREE and FOUR and FIVE and SIX and SEVEN and EIGHT and NINE and TEN)' # policy for ABE
        CTabe = cpabe.encrypt(pk, key_sym_seed, policy_str) #encryption
        key_sym_seed_dec = cpabe.decrypt(pk, CTabe, key_abe)

    time_setup_keygen_ABE_Enc_ABE_Dec_iter = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_ABE_Dec,
                     number = 500))/500
    time_ABE_Dec_iter = time_setup_keygen_ABE_Enc_ABE_Dec_iter - time_setup_ABE_Enc_iter - time_keygen_iter
    print ("Mean time per iteration for ABE Decryption [s] ->", time_ABE_Dec_iter)


    # run the symmetric encryption.
    # Time required to encrypt the message will depend on the size of said message
    def my_SymEnc ():
        key_sym_seed = groupObj.random(GT)
        msg = b"hello world this is an important message."   
        cipher_enc = AuthenticatedCryptoAbstraction(sha2(key_sym_seed)) #AES instantiation with key_sym_seed
        CTaes = cipher_enc.encrypt(msg) # AES message encryption
    time_symenc_iter = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_SymEnc,
                     number = 500))/500
    print ("Mean time per iteration for symmetric encryption [s] ->", time_symenc_iter)
    
    # run the symmetric decryption.
    # Time required to decrypt the message will depend:
    #   - on the size of said message
    #   - on the complexity of the ABE policy used to encrypt the symmetric key (i.e., the amoun of attributes in the policy)
    def my_SymDec ():
        key_sym_seed = groupObj.random(GT)
        msg = b"hello world this is an important message."   
        cipher_enc = AuthenticatedCryptoAbstraction(sha2(key_sym_seed)) #AES instantiation with key_sym_seed
        CTaes = cipher_enc.encrypt(msg) # AES message encryption
        cipher_dec = AuthenticatedCryptoAbstraction(sha2(key_sym_seed))
        msg_dec = cipher_dec.decrypt(CTaes)
        assert msg_dec == msg, "Failed AES Decryption!"
    timecomplete_iter = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_SymDec,
                     number = 500))/500
    time_symdec_iter = timecomplete_iter - time_symenc_iter
    print ("Mean time per iteration for symmetric decryption [s] ->", time_symdec_iter)

if __name__ == "__main__":
    debug = True
    main()