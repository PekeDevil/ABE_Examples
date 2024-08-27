// 10 ATRIBUTOS
use rabe::schemes::yct14::*;
use rabe::utils::policy::pest::PolicyLanguage;

pub fn my_setupyct14 () {
        let (_pk, _msk) = setup(vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()]);
}

pub fn setup_keygen_yct14 () {
    let (pk, msk) = setup(vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()]);
    let policy = String::from(r#"(((("A" and "B") and ("C" and "D")) and ("E" and "F")) and ("G" and "H")) and ("I" and "J")"#);
    let _sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
}


pub fn setup_encrypt_yct14 () {
    let (pk, _msk) = setup(vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()]);

    let plaintext = String::from("hello world this is an important message,").into_bytes();
    let _ct_kp: Yct14AbeCiphertext = encrypt(&pk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()], &plaintext).unwrap();
}


pub fn setup_keygen_encrypt_decrypt_yct14 (){
    let (pk, msk) = setup(vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()]);

    let plaintext = String::from("hello world this is an important message,").into_bytes();
    let policy = String::from(r#"(((("A" and "B") and ("C" and "D")) and ("E" and "F")) and ("G" and "H")) and ("I" and "J")"#);
    let ct_kp: Yct14AbeCiphertext = encrypt(&pk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string(), "E".to_string(),
          "F".to_string(), "G".to_string(), "H".to_string(), "I".to_string(), "J".to_string()], &plaintext).unwrap();    
    let sk: Yct14AbeSecretKey = keygen(&pk, &msk, &policy, PolicyLanguage::HumanPolicy).unwrap();
    assert_eq!(decrypt(&sk, &ct_kp).unwrap(), plaintext); 
}
