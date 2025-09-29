// Copyright (c) 2025 Huzeyfe Çağılcı

/* A test to generate a random key,
   encrypt a char array and decrypt it
   with that key. */

#include "crypto.h"
#include <cstring>
#include <iostream>

using namespace SimpleCrypto;

int main()
{
    setlocale(LC_ALL, "en_US.UTF-8");

    Key key = generateKey(8);
    std::cout << "Generated Key: " << key.getKeyStr() << std::endl;
    Crypto0 crypto(key);

    std::string d = "Hattı müdaafa yoktur, sathı müdafaa vardır. O satıh "
                    "bütün vatandır. Vatanın her karış toprağı, vatandaşın "
                    "kanıyla ıslanmadıkça, terke tabi değildir.";

    std::vector<char> data(d.begin(), d.end());
    int dataSize = data.size();

    auto encrypted_data = crypto.encrypt(data);
    auto decrypted_data = crypto.decrypt(encrypted_data);

    bool success = true;

    for (auto i = 0; i < dataSize; i++)
    {
        if (data[i] != decrypted_data[i])
        {
            std::cout << "Decryption failed: " << i << std::endl;
            success = false;
        }
    }

    if (!success)
        return -1;

    std::cout << std::endl << "Original Data (hex):" << std::endl;
    printhex(data);

    std::cout << std::endl << "Encrypted Data:" << std::endl;
    printhex(encrypted_data);

    decrypted_data.push_back(0);
    std::cout << std::endl << "Decrypted Data: " << decrypted_data.data() << std::endl;
}