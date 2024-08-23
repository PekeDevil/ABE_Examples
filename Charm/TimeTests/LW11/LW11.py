# Required imports from the library:
from time import time
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.dabe_aw11 import Dabe
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.core.math.pairing import hashPair as sha2

# Required import to take time measurements:
import timeit

def main():
    # instantiate a bilinear pairing map
    groupObj = PairingGroup('SS512')
    dabe = Dabe(groupObj)

    # run the set up
    def my_setup ():
        GlobalParam = dabe.setup()    
    # Measure the time taken to run the setup. We run the function 500 times and get the total time required. 
    time_setup= (timeit.timeit(setup = "gc.enable()",
                     stmt = my_setup,
                     number = 500))/500
    print ("Mean time per iteration for setup [s] ->", time_setup)


    # run the set up
    # In LW11_AuthorityDefinitions.md you have more authority setup examples
    def my_AuthoritySetup ():
        GlobalParam = dabe.setup()
        Authority_1 = ['ONE', 'TWO']
        Authority_2 = ['THREE', 'FOUR']       
        Authority_3 = ['FIVE', 'SIX']       
        Authority_4 = ['SEVEN', 'EIGHT']
        Authority_5 = ['NINE', 'TEN']       
        (msk_1, mpk_1) = dabe.authsetup(GlobalParam, Authority_1)
        (msk_2, mpk_2) = dabe.authsetup(GlobalParam, Authority_2)
        (msk_3, mpk_3) = dabe.authsetup(GlobalParam, Authority_3)
        (msk_4, mpk_4) = dabe.authsetup(GlobalParam, Authority_4)
        (msk_5, mpk_5) = dabe.authsetup(GlobalParam, Authority_5)
        mpk = {}
        mpk.update(mpk_1)
        mpk.update(mpk_2)
        mpk.update(mpk_3)
        mpk.update(mpk_4)
        mpk.update(mpk_5)
    # Measure the time taken to run the Authority Setup. We run the function 500 times and get the total time required. 
    time_setup_Authority= (timeit.timeit(setup = "gc.enable()",
                     stmt = my_AuthoritySetup,
                     number = 500))/500
    time_Authority = time_setup_Authority - time_setup
    print ("Mean for setting up 5 Authorities [s] ->", time_Authority)

    # usr_attrs = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN', 'ELEVEN', 'TWELVE', 'THIRTEEN', 'FOURTEEN', 'FIVETEEN', 'SIXTEEN', 'SEVENTEEN', 'EIGHTEEN', 'NINETEEN', 'TWENTY']
    # usr_attrs_1 = ['ONE', 'TWO', 'THREE', 'FOUR', 'FIVE', 'SIX', 'SEVEN', 'EIGHT', 'NINE', 'TEN']
    # usr_attrs_2 = ['ELEVEN', 'TWELVE', 'THIRTEEN', 'FOURTEEN', 'FIVETEEN', 'SIXTEEN', 'SEVENTEEN', 'EIGHTEEN', 'NINETEEN', 'TWENTY']

    # run the key generation.
    # the users can have as many attributes as desired. However, more attributes require more time.
    def my_keygen ():
        GlobalParam = dabe.setup()   
        Authority_1 = ['ONE', 'TWO']
        Authority_2 = ['THREE', 'FOUR']       
        Authority_3 = ['FIVE', 'SIX']       
        Authority_4 = ['SEVEN', 'EIGHT']
        Authority_5 = ['NINE', 'TEN']               
        (msk_1, mpk_1) = dabe.authsetup(GlobalParam, Authority_1)
        (msk_2, mpk_2) = dabe.authsetup(GlobalParam, Authority_2)
        (msk_3, mpk_3) = dabe.authsetup(GlobalParam, Authority_3)
        (msk_4, mpk_4) = dabe.authsetup(GlobalParam, Authority_4)
        (msk_5, mpk_5) = dabe.authsetup(GlobalParam, Authority_5)
        mpk = {}
        mpk.update(mpk_1)
        mpk.update(mpk_2)
        mpk.update(mpk_3)
        mpk.update(mpk_4)
        mpk.update(mpk_5)

        user_ID, SK = "bob", {}
        
        usr_attrs_1 = ['ONE', 'TWO']
        usr_attrs_2 = ['THREE', 'FOUR'] 
        usr_attrs_3 = ['FIVE', 'SIX']
        usr_attrs_4 = ['SEVEN', 'EIGHT']
        usr_attrs_5 = ['NINE', 'TEN']
        for i in usr_attrs_1:  dabe.keygen (GlobalParam, msk_1, i, user_ID, SK) 
        for i in usr_attrs_2:  dabe.keygen (GlobalParam, msk_2, i, user_ID, SK)
        for i in usr_attrs_3:  dabe.keygen (GlobalParam, msk_3, i, user_ID, SK) 
        for i in usr_attrs_4:  dabe.keygen (GlobalParam, msk_4, i, user_ID, SK)
        for i in usr_attrs_5:  dabe.keygen (GlobalParam, msk_5, i, user_ID, SK)
    # Measure the time taken to run keygen for 5 users
    time_setup_Authority_keygen = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_keygen,
                     number = 500))/500
    time_keygen = time_setup_Authority_keygen - time_setup_Authority
    print ("Mean time per iteration to generate the secret keys of five users [s] ->", time_keygen)

    # run the ABE encryption. policy_str can contain as many attributes as desired.
    # In this scheme, ABE is used to encrypt a the symmetric key that will later be used to encrypt the actual message.
    # AND policies are always more time-consuming than OR policies. More attributes also mean more time.
    def my_DABE_Enc ():
        GlobalParam = dabe.setup()   
        Authority_1 = ['ONE', 'TWO']
        Authority_2 = ['THREE', 'FOUR']       
        Authority_3 = ['FIVE', 'SIX']       
        Authority_4 = ['SEVEN', 'EIGHT']
        Authority_5 = ['NINE', 'TEN']           
        (msk_1, mpk_1) = dabe.authsetup(GlobalParam, Authority_1)
        (msk_2, mpk_2) = dabe.authsetup(GlobalParam, Authority_2)
        (msk_3, mpk_3) = dabe.authsetup(GlobalParam, Authority_3)
        (msk_4, mpk_4) = dabe.authsetup(GlobalParam, Authority_4)
        (msk_5, mpk_5) = dabe.authsetup(GlobalParam, Authority_5)
        mpk = {}
        mpk.update(mpk_1)
        mpk.update(mpk_2)
        mpk.update(mpk_3)
        mpk.update(mpk_4)
        mpk.update(mpk_5)
        key_sym_seed = groupObj.random(GT)
        policy_str = '(ONE and TWO and THREE and FOUR and FIVE and SIX and SEVEN and EIGHT and NINE and TEN)' # policy for ABE        
        CTabe = dabe.encrypt(GlobalParam, mpk, key_sym_seed, policy_str) #encryption
    # Measure the time taken to run ABE encryption
    time_setup_Authority_ABE_Enc = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_DABE_Enc,
                     number = 500))/500
    time_ABE_Enc = time_setup_Authority_ABE_Enc - time_setup_Authority
    print ("Mean time per iteration for ABE encryption [s] ->", time_ABE_Enc)


    def my_DABE_Dec ():
        GlobalParam = dabe.setup()   
        Authority_1 = ['ONE', 'TWO']
        Authority_2 = ['THREE', 'FOUR']       
        Authority_3 = ['FIVE', 'SIX']       
        Authority_4 = ['SEVEN', 'EIGHT']
        Authority_5 = ['NINE', 'TEN']          
        (msk_1, mpk_1) = dabe.authsetup(GlobalParam, Authority_1)
        (msk_2, mpk_2) = dabe.authsetup(GlobalParam, Authority_2)
        (msk_3, mpk_3) = dabe.authsetup(GlobalParam, Authority_3)
        (msk_4, mpk_4) = dabe.authsetup(GlobalParam, Authority_4)
        (msk_5, mpk_5) = dabe.authsetup(GlobalParam, Authority_5)
        mpk = {}
        mpk.update(mpk_1)
        mpk.update(mpk_2)
        mpk.update(mpk_3)
        mpk.update(mpk_4)
        mpk.update(mpk_5)
        key_sym_seed = groupObj.random(GT)        
        user_ID, SK = "bob", {}
        usr_attrs_1 = ['ONE', 'TWO']
        usr_attrs_2 = ['THREE', 'FOUR'] 
        usr_attrs_3 = ['FIVE', 'SIX']
        usr_attrs_4 = ['SEVEN', 'EIGHT']
        usr_attrs_5 = ['NINE', 'TEN']
        for i in usr_attrs_1:  dabe.keygen (GlobalParam, msk_1, i, user_ID, SK) 
        for i in usr_attrs_2:  dabe.keygen (GlobalParam, msk_2, i, user_ID, SK)
        for i in usr_attrs_3:  dabe.keygen (GlobalParam, msk_3, i, user_ID, SK) 
        for i in usr_attrs_4:  dabe.keygen (GlobalParam, msk_4, i, user_ID, SK)
        for i in usr_attrs_5:  dabe.keygen (GlobalParam, msk_5, i, user_ID, SK)
        policy_str = '(ONE and TWO and THREE and FOUR and FIVE and SIX and SEVEN and EIGHT and NINE and TEN)' # policy for ABE        
        CTabe = dabe.encrypt(GlobalParam, mpk, key_sym_seed, policy_str) #encryption
        key_sym_seed_dec = dabe.decrypt(GlobalParam, SK, CTabe)
    time_setup_Authority_keygen_ABE_Enc_ABE_Dec = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_DABE_Dec,
                     number = 500))/500
    time_ABE_Dec = time_setup_Authority_keygen_ABE_Enc_ABE_Dec - time_setup_Authority_ABE_Enc - time_keygen
    print ("Mean time per iteration for ABE Decryption [s] ->", time_ABE_Dec)

    # run the symmetric encryption.
    # Time required to encrypt the message will depend on the size of said message
    def my_SymEnc ():
        key_sym_seed = groupObj.random(GT)
        msg = b"hello world this is an important message."   
        cipher_enc = AuthenticatedCryptoAbstraction(sha2(key_sym_seed)) #AES instantiation with key_sym_seed
        CTaes = cipher_enc.encrypt(msg) # AES message encryption
    time_symenc = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_SymEnc,
                     number = 500))/500
    print ("Mean time per iteration for symmetric encryption [s] ->", time_symenc)


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
    timecomplete = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_SymDec,
                     number = 500))/500
    time_symdec = timecomplete - time_symenc
    print ("Mean time per iteration for symmetric decryption [s] ->", time_symdec)

if __name__ == "__main__":
    debug = True
    main()