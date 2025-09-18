// Copyright (c) 2025 Huzeyfe Çağılcı

/* A test to generate a random key,
   encrypt a char array and decrypt it
   with that key. */

#include "crypto.h"
#include <iostream>

using namespace SimpleCrypto;

int main()
{
    setlocale(LC_ALL, "en_US.UTF-8");

    Key key = generateKey(8);
    std::cout << "Generated Key: " << key.getKeyStr() << std::endl;
    Crypto0 crypto(key);

    const char *data = "Hattı müdaafa yoktur, sathı müdafaa vardır. O satıh "
                       "bütün vatandır. Vatanın her karış toprağı, vatandaşın "
                       "kanıyla ıslanmadıkça, terke tabi değildir.";

    unsigned int dataSize = strlen(data) + 1;

    char *encrypted_data = crypto.encrypt(data, dataSize);
    char *decrypted_data = crypto.decrypt(encrypted_data, dataSize);

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
    printhex(data, dataSize);

    std::cout << std::endl << "Encrypted Data:" << std::endl;
    printhex(encrypted_data, dataSize);

    std::cout << std::endl << "Decrypted Data: " << decrypted_data << std::endl;

    delete[] encrypted_data;
    delete[] decrypted_data;
}