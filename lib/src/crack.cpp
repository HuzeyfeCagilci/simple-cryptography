// Copyright (c) 2025 Huzeyfe Çağılcı

/*  A test to crack encrypted data without knowing the key. */

/*  If the first character of the original data is known,
    a large portion of the data can be decrypted. Shuffling
    does not offer much security. Therefore, this encryption
    algorithm is not secure.
*/

#include "crypto.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

using namespace SimpleCrypto;

int main()
{
    setlocale(LC_ALL, "en_US.UTF-8");

    std::ifstream f("test1.sckey");
    if (!f.good())
    {
        std::cerr << "test1.sckey did not found." << std::endl;
        return 1;
    }
    f.close();

    Key key(std::string("test1.sckey"));
    std::cout << "Read Key: " << key.getKeyStr() << std::endl;
    Crypto0 crypto(key);

    const char *data = "Hattı müdaafa yoktur, sathı müdafaa vardır. O satıh "
                       "bütün vatandır. Vatanın her karış toprağı, vatandaşın "
                       "kanıyla ıslanmadıkça, terke tabi değildir.";

    unsigned int dataSize = strlen(data) + 1;

    char *encrypted_data = crypto.encrypt(data, dataSize);

    for (int i = 0; i < dataSize - 1; i++)
    {
        std::cout << std::hex << (data[i] ^ encrypted_data[i]) << std::endl;
    }

    std::cout << std::endl;

    char cons = data[0] ^ encrypted_data[0];

    for (int i = 0; i < dataSize - 1; i++)
    {
        std::cout << (char)(encrypted_data[i] ^ cons);
    }

    std::cout << std::endl;
}