// IMPORTS FOR OPEnumAttributesBE
#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

// IMPORTS FOR TIME MEASUREMENT
#include <ctime>
#include <chrono>
#include <fstream>

// numAttributesMESPACES
using namespace std;
using namespace oabe;
using namespace oabe::crypto;
using namespace std::chrono;

//MAIN
int main()
{
    ////////////// FILENAME //////////////
    time_t now = time(0);
    struct tm *ltm = localtime(&now); // ltm has DD MM DD hh:mm:ss AAAA

    std::string s_ltm = asctime(ltm);
    s_ltm.pop_back();
    std::replace(s_ltm.begin(), s_ltm.end(), ' ', '_'); // replace all ' ' to '_'
    std::replace(s_ltm.begin(), s_ltm.end(), ':', '_'); // replace all ':' to '_'
    std::string s_filename = "W11_TimeTest" + s_ltm + ".csv";

    ////////////// CREATE FILE //////////////
    fstream datafile;
    datafile.open(s_filename.c_str(), ios::out | ios::app);

    // Add a header to the file
    if (datafile.is_open())
    {
        datafile << "Attribute Number"
                     << ", "
                     << "Test N"
                     << ", "
                     << "Function"
                     << ", "
                     << "Time (ms)"
                     << ", "
                     << "Key Size (bytes)"
                     << ", "
                     << "CT Size (bytes)"
                     << ", "
                     << "PT Size (bytes)"
                     << "\n";
    }
    else
        cout << "File does not exist or permissions to open it are missing" << endl;
        return 1;
    datafile.close();

    std::string UserAtts = "|";
    std::string accesspolicyBody = "";
    std::string newPolicy = "";
    std::string accesspolicy = "";

    // A loop is generated that increases the number of attributes contained in the SK and in the policy.
    // This way we test how the number of attributes affect the execution time of the different functions.
    
    for (int numAttributes = 0; numAttributes < 10; numAttributes++) // numAttributes stands for the amount of attributes
    {
        auto attribute_number = std::to_string(numAttributes + 1);

        // Prepare access attributes and policies
        std::string s_numAttributes = to_string(numAttributes);
        std::string newPolicy = "att" + s_numAttributes;
        std::string newAtt = newPolicy + "|";
        UserAtts = UserAtts + newAtt;

        if (numAttributes == 0)
        {
            accesspolicyBody = accesspolicyBody + newPolicy;
        }
        else
        {
            accesspolicyBody = accesspolicyBody + " AND " + newPolicy;
        }

        accesspolicy = "(" + accesspolicyBody + ")";

        for (int execCount = 0; execCount < 100; execCount = execCount + 1) // Number of executions in order to obtain the average time.
        {
            auto iteration = std::to_string(execCount + 1);

            ////////////// ABE INITIALIZATION //////////////
            InitializeOpenABE();
            OpenABECryptoContext cpabe("CP-ABE"); // Create a new W11 CP-ABE context

            ///////////////////////////// SETUP ///////////////////////////////////
            cpabe.generateParams();
            std::string mpk;
            cpabe.exportPublicParams(mpk);
            std::string msk;
            cpabe.exportSecretParams(msk);

            /////////////////////////// KEY GENERATION ////////////////////////////
            std::string user_SKBlob = "";

            auto startKG = high_resolution_clock::now();
            cpabe.keygen(UserAtts, "user_SK"); //stored in an in-memory keystore
            cpabe.exportUserKey("user_SK", user_SKBlob);
            auto stopKG = high_resolution_clock::now();

            auto KeyGenerationTime = duration_cast<milliseconds>(stopKG - startKG);
            std::string s_KeyGenerationTime = std::to_string(KeyGenerationTime.count());
            auto KeySize = user_SKBlob.length();

            datafile.open(s_filename.c_str(), ios::out | ios::app);
            if (datafile.is_open())
            {
                datafile << attribute_number
                             << ", "
                             << iteration
                             << ","
                             << "Key generation"
                             << ", "
                             << s_KeyGenerationTime
                             << ", "
                             << KeySize
                             << ", "
                             << "------"
                             << ", "
                             << "------"
                             << "\n";
            }
            else
                cout << "File does not exist or permissions to open it are missing" << endl;
                return 1;

            ////////////////////////////// ENCRYPTION /////////////////////////////
            std::string CT = "";
            std::string PT = "hello world this is an important message";
            std::string decrypted_CT = "";

            auto PTSize = PT.length();

            auto startENC = high_resolution_clock::now();
            cpabe.importPublicParams(mpk); 

            // ABE & AES-GCM encryption in one step
            cpabe.encrypt(accesspolicy, PT, CT);
            auto stopENC = high_resolution_clock::now();
            auto CTSize = CT.length();

            auto EncryptionTime = duration_cast<milliseconds>(stopENC - startENC);
            std::string s_EncryptionTime = std::to_string(EncryptionTime.count());

            if (datafile.is_open())
            {
                datafile << attribute_number
                             << ", "
                             << iteration
                             << ","
                             << "Encryption"
                             << ", "
                             << s_EncryptionTime
                             << ", "
                             << KeySize
                             << ", "
                             << CTSize
                             << ", "
                             << PTSize
                             << "\n";
            }
            else
                cout << "File does not exist or permissions to open it are missing" << endl;
                return 1;

            ////////////////////////////// DECRYPTION /////////////////////////////
            auto startDEC = high_resolution_clock::now();

            bool result = cpabe.decrypt("user_SK", CT, decrypted_CT);
            assert(result && PT == decrypted_CT); 

            auto stopDEC = high_resolution_clock::now();
            auto DecryptionTime = duration_cast<milliseconds>(stopDEC - startDEC);
            string s_DecryptionTime = std::to_string(DecryptionTime.count());

            if (datafile.is_open())
            {
                datafile << attribute_number
                             << ", "
                             << iteration
                             << ","
                             << "Decryption"
                             << ", "
                             << s_DecryptionTime
                             << ", "
                             << KeySize
                             << ", "
                             << CTSize
                             << ", "
                             << PTSize
                             << "\n";
            }
            else
                cout << "File does not exist or permissions to open it are missing" << endl;
                return 1;

            ShutdownOpenABE();
            datafile.close();
            cout << "Finished iteration " + iteration << endl;
        }
    }
    return 0;
}