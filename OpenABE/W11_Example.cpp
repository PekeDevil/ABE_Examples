// IMPORTS FOR OPENABE
#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

// IMPORTS FOR TIME MEASUREMENT
#include <ctime>
#include <chrono>
#include <fstream>

// NAMESPACES
using namespace std;
using namespace oabe;
using namespace oabe::crypto;
using namespace std::chrono;

//MAIN
int main()
{
    ////////////// ABE INITIALIZATION //////////////
    InitializeOpenABE();
    OpenABECryptoContext cpabe("CP-ABE"); // Create a new W11 CP-ABE context

    ///////////////////////////// SETUP ///////////////////////////////////
    /*Setup is usually run by the administrator*/
    cpabe.generateParams(); /* generate fresh master public and secret parameters stored in an in-memory keystore.*/

    std::string mpk;
    cpabe.exportPublicParams(mpk); /*The mpk can be stored/cached on the file system or in a database.*/

    std::string msk;
    cpabe.exportSecretParams(msk); /*The msk must be kept secret and protected wherever it is stored.*/


    ///////////////////////////KEY GENERATION////////////////////////////
    /*KeyGen is usually run by the administrator*/
    std::string SK_Blob = "";
    std::string UserAtts = "|att0|att1|att2|att3|att4|att5|att6|att7|att8|att9|";

    cpabe.keygen(UserAtts, "SK"); /* stored in an in-memory keystore*/
    cpabe.exportUserKey("SK", SK_Blob); /*The exported string can be stored on the file system or a database depending on the application, but must be kept secret and protected on disk.*/


    //////////////////////////////ENCRYPTION/////////////////////////////
    std::string CT = "";
    std::string PT = "hello world this is an important message";
    std::string decrypted_CT = "";

    // cpabe.importPublicParams(mpk); /*If running on different machines, after exporting it, it must be imported in order to encrypt*/

    // ABE & AES-GCM encryption in one step
    std::string accesspolicy = "(att0 AND att1 AND att2 AND att3 AND att4 AND att5 AND att6 AND att7 AND att8 AND att9)";
    cpabe.encrypt(accesspolicy, PT, CT);

    //////////////////////////////DECRYPTION/////////////////////////////
    bool result = cpabe.decrypt("SK", CT, decrypted_CT);
    assert(result && PT == decrypted_CT);

    ShutdownOpenABE();
    return 0;
}