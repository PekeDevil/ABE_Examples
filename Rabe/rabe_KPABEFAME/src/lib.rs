// 10 ATRIBUTOS
use rabe::schemes::ac17::*;
use rabe::utils::policy::pest::PolicyLanguage;


pub fn my_setupac17kpabe () {
    let (_pk, _msk) = setup();
}

pub fn setup_keygen () {
    let (_pk, msk) = setup();
    let policy = String::from(r#"(((("A" and "B") and ("C" and "D")) and ("E" and "F")) and ("G" and "H")) and ("I" and "J")"#);
    let _sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
}

pub fn setup_encryptac17kpabe () {
    let (pk, _msk) = setup();
    let plaintext = String::from("hello world this is an important message,").into_bytes();
    //let plaintext = String::from(".").into_bytes();
    let _ct: Ac17KpCiphertext =  kp_encrypt(&pk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()], &plaintext).unwrap();
}

pub fn setup_keygen_encrypt_decryptac17kpabe (){
    let (pk, msk) = setup();
    let policy = String::from(r#"(((("A" and "B") and ("C" and "D")) and ("E" and "F")) and ("G" and "H")) and ("I" and "J")"#);
    let sk: Ac17KpSecretKey = kp_keygen(&msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
    let plaintext = String::from("hello world this is an important message,").into_bytes();
    //let plaintext = String::from(".").into_bytes();
    let ct: Ac17KpCiphertext =  kp_encrypt(&pk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()], &plaintext).unwrap();
    assert_eq!(kp_decrypt(&sk, &ct).unwrap(), plaintext);
}