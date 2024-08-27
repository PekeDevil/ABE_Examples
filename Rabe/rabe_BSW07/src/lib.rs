//1 ATRIBUTOS 
use rabe::schemes::bsw::*;
use rabe::utils::policy::pest::PolicyLanguage;


pub fn my_setup_BSW07 () {
    let (pk, msk) = setup();
}

// "A" is an attribute. It can have more than one attribute (it means more time for key generation)
// for example for 5 attributes:
// let sk: CpAbeSecretKey = keygen(&pk, &msk, &vec!["A".to_string(),
//              "B".to_string(),
//              "C".to_string(),
//              "D".to_string(),
//              "E".to_string()]).unwrap();
pub fn setup_keygen_BSW07 () {
    let (pk, msk) = setup();
    let sk: CpAbeSecretKey = keygen(&pk, &msk, &vec!["A".to_string()]).unwrap();
}



// (r#""A""#) is an policy. It can have more than one policy (it means more time for encryption and decryption).
// for example for a policy with 5 attributes:
// let policy = String::from(r#"(("A" and "B") and ("C" and "D")) and "E""#);
pub fn setup_encrypt_BSW07 () {
    let (pk, msk) = setup();
    let plaintext = String::from("hello world this is an important message,").into_bytes();
    let policy = String::from(r#""A""#);
    let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
}

// This function is the combination of the previous functions and decryption.
pub fn setup_keygen_encrypt_BSW07 (){
    let (pk, msk) = setup();
    let plaintext = String::from("hello world this is an important message,").into_bytes();
    let policy = String::from(r#""A""#);
    let ct_cp: CpAbeCiphertext = encrypt(&pk, &policy, &plaintext, PolicyLanguage::HumanPolicy).unwrap();
    let sk: CpAbeSecretKey = keygen(&pk, &msk, &vec!["A".to_string()]).unwrap();
    assert_eq!(decrypt(&sk, &ct_cp).unwrap(), plaintext);    
}

