// 20 ATRIBUTOS
use rabe::schemes::aw11::*;
use rabe::utils::policy::pest::PolicyLanguage;

pub fn my_setup_lw11 () {
    let gk = setup();
}

pub fn setup_authssetup_lw11 () {
    let gk = setup();
    let (pk_01, msk01) = authgen(&gk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()]).unwrap();
    let (pk_02, msk02) = authgen(&gk, &vec!["E".to_string(), "F".to_string(), "G".to_string(), "H".to_string()]).unwrap();
    let (pk_03, msk03) = authgen(&gk, &vec!["I".to_string(), "J".to_string(), "K".to_string(), "L".to_string()]).unwrap();
    let (pk_04, msk04) = authgen(&gk, &vec!["M".to_string(), "N".to_string(), "O".to_string(), "P".to_string()]).unwrap();
    let (pk_05, msk05) = authgen(&gk, &vec!["Q".to_string(), "R".to_string(), "S".to_string(), "T".to_string()]).unwrap();
}

pub fn setup_authssetup_keygen_lw11() {
    let gk = setup();
    let (pk_01, msk01) = authgen(&gk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()]).unwrap();
    let (pk_02, msk02) = authgen(&gk, &vec!["E".to_string(), "F".to_string(), "G".to_string(), "H".to_string()]).unwrap();
    let (pk_03, msk03) = authgen(&gk, &vec!["I".to_string(), "J".to_string(), "K".to_string(), "L".to_string()]).unwrap();
    let (pk_04, msk04) = authgen(&gk, &vec!["M".to_string(), "N".to_string(), "O".to_string(), "P".to_string()]).unwrap();
    let (pk_05, msk05) = authgen(&gk, &vec!["Q".to_string(), "R".to_string(), "S".to_string(), "T".to_string()]).unwrap();

    let mut bob_sk = keygen(&gk, &msk01, &String::from("bob"), &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()]).unwrap(); // a slice of the SK is created
    add_to_attribute(&gk, &msk02, &"E".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk02, &"F".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk02, &"G".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk02, &"H".to_string(), &mut bob_sk).unwrap(); // added to the SK

    add_to_attribute(&gk, &msk03, &"I".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk03, &"J".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk03, &"K".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk03, &"L".to_string(), &mut bob_sk).unwrap(); // added to the SK

    add_to_attribute(&gk, &msk04, &"M".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk04, &"N".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk04, &"O".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk04, &"P".to_string(), &mut bob_sk).unwrap(); // added to the SK
    
    add_to_attribute(&gk, &msk05, &"Q".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk05, &"R".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk05, &"S".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk05, &"T".to_string(), &mut bob_sk).unwrap(); // added to the SK
}

pub fn setup_authsetup_encrypt_lw11 () {
    let gk = setup();
    let (pk_01, msk01) = authgen(&gk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()]).unwrap();
    let (pk_02, msk02) = authgen(&gk, &vec!["E".to_string(), "F".to_string(), "G".to_string(), "H".to_string()]).unwrap();
    let (pk_03, msk03) = authgen(&gk, &vec!["I".to_string(), "J".to_string(), "K".to_string(), "L".to_string()]).unwrap();
    let (pk_04, msk04) = authgen(&gk, &vec!["M".to_string(), "N".to_string(), "O".to_string(), "P".to_string()]).unwrap();
    let (pk_05, msk05) = authgen(&gk, &vec!["Q".to_string(), "R".to_string(), "S".to_string(), "T".to_string()]).unwrap();
    let plaintext = String::from("hello world this is an important message,").into_bytes();    
    let policy = String::from(r#"((((((((("A" and "B") and ("C" and "D")) and ("E" and "F")) and ("G" and "H")) and ("I" and "J")) and ("K" and "L")) and ("M" and "N")) and ("O" and "P")) and ("Q" and "R")) and ("S" and "T")"#);
    let ct: Aw11Ciphertext = encrypt(&gk, &vec![pk_01, pk_02,pk_03, pk_04, pk_05], &policy, PolicyLanguage::HumanPolicy, &plaintext).unwrap();
}


pub fn setup_authsetup_keygen_encrypt_decrypt_lw11 (){
    let gk = setup();
    let (pk_01, msk01) = authgen(&gk, &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()]).unwrap();
    let (pk_02, msk02) = authgen(&gk, &vec!["E".to_string(), "F".to_string(), "G".to_string(), "H".to_string()]).unwrap();
    let (pk_03, msk03) = authgen(&gk, &vec!["I".to_string(), "J".to_string(), "K".to_string(), "L".to_string()]).unwrap();
    let (pk_04, msk04) = authgen(&gk, &vec!["M".to_string(), "N".to_string(), "O".to_string(), "P".to_string()]).unwrap();
    let (pk_05, msk05) = authgen(&gk, &vec!["Q".to_string(), "R".to_string(), "S".to_string(), "T".to_string()]).unwrap();
    
    let mut bob_sk = keygen(&gk, &msk01, &String::from("bob"), &vec!["A".to_string(), "B".to_string(), "C".to_string(), "D".to_string()]).unwrap(); // a slice of the SK is created
    add_to_attribute(&gk, &msk02, &"E".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk02, &"F".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk02, &"G".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk02, &"H".to_string(), &mut bob_sk).unwrap(); // added to the SK

    add_to_attribute(&gk, &msk03, &"I".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk03, &"J".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk03, &"K".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk03, &"L".to_string(), &mut bob_sk).unwrap(); // added to the SK

    add_to_attribute(&gk, &msk04, &"M".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk04, &"N".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk04, &"O".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk04, &"P".to_string(), &mut bob_sk).unwrap(); // added to the SK
    
    add_to_attribute(&gk, &msk05, &"Q".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk05, &"R".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk05, &"S".to_string(), &mut bob_sk).unwrap(); // added to the SK
    add_to_attribute(&gk, &msk05, &"T".to_string(), &mut bob_sk).unwrap(); // added to the SK


    let plaintext = String::from("hello world this is an important message,").into_bytes();    
    let policy = String::from(r#"((((((((("A" and "B") and ("C" and "D")) and ("E" and "F")) and ("G" and "H")) and ("I" and "J")) and ("K" and "L")) and ("M" and "N")) and ("O" and "P")) and ("Q" and "R")) and ("S" and "T")"#);
    let ct: Aw11Ciphertext = encrypt(&gk, &vec![pk_01, pk_02,pk_03, pk_04, pk_05], &policy, PolicyLanguage::HumanPolicy, &plaintext).unwrap();
    let matching = decrypt(&gk, &bob_sk, &ct).unwrap();
    assert_eq!(matching, plaintext);
}