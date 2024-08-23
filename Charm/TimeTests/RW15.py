# Required imports from the library:
from ast import If
from time import time
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction
from charm.toolbox.pairinggroup import PairingGroup,GT
from charm.core.math.pairing import hashPair as sha2

# Required import to take time measurements:
import timeit

def main():
    # instantiate a bilinear pairing map
    groupObj = PairingGroup('SS512')
    maabe = MaabeRW15(groupObj)

    # run the set up
    def my_setup ():
        public_parameters = maabe.setup()    
    # Measure the time taken to run the setup. We run the function 500 times and get the total time required. 
    time_setup= (timeit.timeit(setup = "gc.enable()",
                     stmt = my_setup,
                     number = 500))/500
    print ("Mean time per iteration for setup [s] ->", time_setup)

    # run the set up
    def my_AuthoritySetup ():
        public_parameters = maabe.setup()  
        (mpk_1, msk_1) = maabe.authsetup(public_parameters, 'Authority_1') #Authorities get a name, for example 'Authority_1'
        (mpk_2, msk_2) = maabe.authsetup(public_parameters, 'Authority_2')
        (mpk_3, msk_3) = maabe.authsetup(public_parameters, 'Authority_3')
        (mpk_4, msk_4) = maabe.authsetup(public_parameters, 'Authority_4')
        (mpk_5, msk_5) = maabe.authsetup(public_parameters, 'Authority_5')

        # The final MPK is composed of the MPK of each authority
        mpk = {'Authority_1': mpk_1, 'Authority_2': mpk_2, 'Authority_3': mpk_3, 'Authority_4': mpk_4, 'Authority_5': mpk_5}
    # Measure the time taken to run the Authority Setup. We run the function 500 times and get the total time required. 
    time_setup_Authority= (timeit.timeit(setup = "gc.enable()",
                     stmt = my_AuthoritySetup,
                     number = 500))/500
    time_Authority = time_setup_Authority - time_setup
    print ("Mean for setting up 5 Authorities [s] ->", time_Authority)

    # run the key generation.
    # the users can have as many attributes as desired. However, more attributes require more time.
    def my_keygen ():
        # Define the user
        user_ID = "bob" # the User ID
        user_SK = {}

        public_parameters = maabe.setup()  
        (mpk_1, msk_1) = maabe.authsetup(public_parameters, 'Authority_1')
        (mpk_2, msk_2) = maabe.authsetup(public_parameters, 'Authority_2')
        (mpk_3, msk_3) = maabe.authsetup(public_parameters, 'Authority_3')
        (mpk_4, msk_4) = maabe.authsetup(public_parameters, 'Authority_4')
        (mpk_5, msk_5) = maabe.authsetup(public_parameters, 'Authority_5')
        mpk = {'Authority_1': mpk_1, 'Authority_2': mpk_2, 'Authority_3': mpk_3, 'Authority_4': mpk_4, 'Authority_5': mpk_5}
        
        # The user is given the attributes by specific authorities
        # for example, the attributes ONE, TWO and ELEVEN are provided by Authority_1
        usr_attrs_1 = ['ONE@Authority_1', 'TWO@Authority_1', 'ELEVEN@Authority_1']
        usr_attrs_2 = ['THREE@Authority_2', 'FOUR@Authority_2', 'TWELVE@Authority_2'] 
        usr_attrs_3 = ['FIVE@Authority_3', 'SIX@Authority_3', 'THIRTEEN@Authority_3']
        usr_attrs_4 = ['SEVEN@Authority_4', 'EIGHT@Authority_4', 'FOURTEEN@Authority_4']
        usr_attrs_5 = ['NINE@Authority_5', 'TEN@Authority_5', 'FIVETEEN@Authority_5']

        # The user keys are composed using the public parameters, the authorities' msks, the user_ID, and users' attributes
        # Note that there there is a single user, but it requires SKs from different authorities
        user_SK1 = maabe.multiple_attributes_keygen(public_parameters, msk_1, user_ID, usr_attrs_1)
        user_SK2 = maabe.multiple_attributes_keygen(public_parameters, msk_2, user_ID, usr_attrs_2)
        user_SK3 = maabe.multiple_attributes_keygen(public_parameters, msk_3, user_ID, usr_attrs_3)
        user_SK4 = maabe.multiple_attributes_keygen(public_parameters, msk_4, user_ID, usr_attrs_4)
        user_SK5 = maabe.multiple_attributes_keygen(public_parameters, msk_5, user_ID, usr_attrs_5)
        
        for dictionary in (user_SK1, user_SK2, user_SK3, user_SK4, user_SK5):
            user_SK.update(dictionary)
        user_SK = {'User ID (aka GID)': user_ID, 'keys': user_SK}
    # Measure the time taken to run keygen
    time_setup_Authority_keygen = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_keygen,
                     number = 500))/500
    time_keygen = time_setup_Authority_keygen - time_setup_Authority
    print ("Mean time per iteration to generate the secret keys of a single users requesting to five authorities [s] ->", time_keygen)

    # run the ABE encryption. policy_str can contain as many attributes as desired.
    # In this scheme, ABE is used to encrypt a the symmetric key that will later be used to encrypt the actual message.
    # AND policies are always more time-consuming than OR policies. More attributes also mean more time.
    def my_ABE_Enc ():
        public_parameters = maabe.setup()  
        (mpk_1, msk_1) = maabe.authsetup(public_parameters, 'Authority_1')
        (mpk_2, msk_2) = maabe.authsetup(public_parameters, 'Authority_2')
        (mpk_3, msk_3) = maabe.authsetup(public_parameters, 'Authority_3')
        (mpk_4, msk_4) = maabe.authsetup(public_parameters, 'Authority_4')
        (mpk_5, msk_5) = maabe.authsetup(public_parameters, 'Authority_5')
        mpk = {'Authority_1': mpk_1, 'Authority_2': mpk_2, 'Authority_3': mpk_3, 'Authority_4': mpk_4, 'Authority_5': mpk_5}

        key_sym_seed = groupObj.random(GT)
        policy_str = '(ONE@Authority_1 and TWO@Authority_1 and THREE@Authority_2 and FOUR@Authority_2 and FIVE@Authority_3 and SIX@Authority_3 and SEVEN@Authority_4 and EIGHT@Authority_4 and NINE@Authority_5 and TEN@Authority_5 and ELEVEN@Authority_1 and TWELVE@Authority_2 and THIRTEEN@Authority_3 and FOURTEEN@Authority_4 and FIVETEEN@Authority_5)' # policy for ABE        
        CTabe = maabe.encrypt(public_parameters, mpk, key_sym_seed, policy_str) #encryption
    # Measure the time taken to run ABE encryption
    time_setup_Authority_ABE_Enc = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_ABE_Enc,
                     number = 500))/500
    time_ABE_Enc = time_setup_Authority_ABE_Enc - time_setup_Authority
    print ("Mean time per iteration for ABE encryption [s] ->", time_ABE_Enc)


    def my_ABE_Dec ():
        # Define the user
        user_ID = "bob" # the User ID
        user_SK = {}

        public_parameters = maabe.setup()  
        (mpk_1, msk_1) = maabe.authsetup(public_parameters, 'Authority_1')
        (mpk_2, msk_2) = maabe.authsetup(public_parameters, 'Authority_2')
        (mpk_3, msk_3) = maabe.authsetup(public_parameters, 'Authority_3')
        (mpk_4, msk_4) = maabe.authsetup(public_parameters, 'Authority_4')
        (mpk_5, msk_5) = maabe.authsetup(public_parameters, 'Authority_5')
        mpk = {'Authority_1': mpk_1, 'Authority_2': mpk_2, 'Authority_3': mpk_3, 'Authority_4': mpk_4, 'Authority_5': mpk_5}

        key_sym_seed = groupObj.random(GT)        
        usr_attrs_1 = ['ONE@Authority_1', 'TWO@Authority_1', 'ELEVEN@Authority_1']
        usr_attrs_2 = ['THREE@Authority_2', 'FOUR@Authority_2', 'TWELVE@Authority_2'] 
        usr_attrs_3 = ['FIVE@Authority_3', 'SIX@Authority_3', 'THIRTEEN@Authority_3']
        usr_attrs_4 = ['SEVEN@Authority_4', 'EIGHT@Authority_4', 'FOURTEEN@Authority_4']
        usr_attrs_5 = ['NINE@Authority_5', 'TEN@Authority_5', 'FIVETEEN@Authority_5']
        user_SK1 = maabe.multiple_attributes_keygen(public_parameters, msk_1, user_ID, usr_attrs_1)
        user_SK2 = maabe.multiple_attributes_keygen(public_parameters, msk_2, user_ID, usr_attrs_2)
        user_SK3 = maabe.multiple_attributes_keygen(public_parameters, msk_3, user_ID, usr_attrs_3)
        user_SK4 = maabe.multiple_attributes_keygen(public_parameters, msk_4, user_ID, usr_attrs_4)
        user_SK5 = maabe.multiple_attributes_keygen(public_parameters, msk_5, user_ID, usr_attrs_5)

        for dictionary in (user_SK1, user_SK2, user_SK3, user_SK4, user_SK5):
            user_SK.update(dictionary)
        user_SK = {'GID': user_ID, 'keys': user_SK}

        policy_str = '(ONE@Authority_1 and TWO@Authority_1 and THREE@Authority_2 and FOUR@Authority_2 and FIVE@Authority_3 and SIX@Authority_3 and SEVEN@Authority_4 and EIGHT@Authority_4 and NINE@Authority_5 and TEN@Authority_5 and ELEVEN@Authority_1 and TWELVE@Authority_2 and THIRTEEN@Authority_3 and FOURTEEN@Authority_4 and FIVETEEN@Authority_5)' # policy for ABE        
        CTabe = maabe.encrypt(public_parameters, mpk, key_sym_seed, policy_str) #encryption
        key_sym_seed_dec = maabe.decrypt(public_parameters, user_SK, CTabe)          
    time_setup_Authority_keygen_ABE_Enc_ABE_Dec = (timeit.timeit(setup = "gc.enable()",
                     stmt = my_ABE_Dec,
                     number = 500))/500
    time_ABE_Dec = time_setup_Authority_keygen_ABE_Enc_ABE_Dec - time_setup_Authority_ABE_Enc - time_keygen
    print ("ABE_DecMean time per iteration for ABE Decryption [s] ->", time_ABE_Dec)

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

