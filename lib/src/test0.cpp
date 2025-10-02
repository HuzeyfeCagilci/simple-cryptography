// Copyright (c) 2025 Huzeyfe Çağılcı

/* A test to generate a random key,
   encrypt a char array and decrypt it
   with that key. */

#include "crypto.h"
#include <cstring>
#include <iostream>

using namespace SimpleCrypto;

void testCrypto(Crypto &crypto, std::vector<char> &data)
{
    int dataSize = data.size();

    auto encrypted_data = crypto.encrypt(data);
    auto decrypted_data = crypto.decrypt(encrypted_data);

    for (long i = 0; i < decrypted_data.size(); i++)
    {
        if (data[i] != decrypted_data[i])
        {
            std::cout << "Decryption failed: " << i << std::endl;
        }
    }

    // std::cout << std::endl << "Original Data (hex):" << std::endl;
    // printhex(data);

    std::cout << std::endl << "Encrypted Data:" << std::endl;
    printhex(encrypted_data);

    std::cout << std::endl << "Decrypted Data: ";
    std::cout.write(decrypted_data.data(), dataSize);
    std::cout << std::endl;
}

int main()
{
    setlocale(LC_ALL, "en_US.UTF-8");

    Key key = generateKey(128);
    std::cout << "Generated Key: " << key.getKeyStr() << std::endl;

    Crypto0 crypto0(key);
    Crypto1 crypto1(key);

    Key extendedKey = extendKey(key);

    Crypto1 crypto1E(extendedKey);

    std::string d = "Hattı müdaafa yoktur, sathı müdafaa vardır. O satıh "
                    "bütün vatandır. Vatanın her karış toprağı, vatandaşın "
                    "kanıyla ıslanmadıkça, terke tabi değildir.";

    std::vector<char> data(d.begin(), d.end());

    testCrypto(crypto0, data);
    testCrypto(crypto1, data);
    testCrypto(crypto1E, data);
}