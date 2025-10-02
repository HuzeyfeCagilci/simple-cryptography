// Copyright (c) 2025 Huzeyfe Çağılcı

/*  A test to crack encrypted data without knowing the key. */

/*  For Crypto0 class:

    encrypted[i] = data[i] ^ key[0] ^ key[1] ^ ... ^ key[n]

    x = key[0] ^ ... ^ key[n]

    So,

    encrypted[i] = data[i] ^ x

    If the first character of the original data is known,
    a large portion of the ciphertext encrypted with a
    short key can be recovered. Simple shuffling does not
    provide strong security.

    However, if the key is sufficiently long, breaking the
    encryption becomes significantly more difficult. Unless
    shuffle, the ciphertext can be recovered regardless of
    the key length.
*/

#include "crypto.h"
#include <cstring>
#include <iostream>
#include <string>

using namespace SimpleCrypto;

void crack(Crypto &crypto, std::vector<char> &data)
{
    auto encrypted_data = crypto.encrypt(data);
    int dataSize = data.size();

    /*for (int i = 0; i < dataSize - 1; i++)
    {
        std::cout << std::hex << (data[i] ^ encrypted_data_0[i]) << std::endl;
    }*/

    std::cout << std::endl;

    char x = data[0] ^ encrypted_data[0];

    for (int i = 0; i < dataSize - 1; i++)
    {
        std::cout << (char)(encrypted_data[i] ^ x);
    }

    std::cout << std::endl;
}

int main()
{
    setlocale(LC_ALL, "en_US.UTF-8");

    Key key_0 = generateKey(8);
    Key key_1 = generateKey(128);

    std::cout << "Key_0: " << key_0.getKeyStr() << std::endl;
    std::cout << "Key_1: " << key_1.getKeyStr() << std::endl;

    Crypto0 crypto_0(key_0);
    Crypto0 crypto_1(key_1);
    Crypto0 crypto_2(key_0);
    Crypto0 crypto_3(key_1);

    Crypto1 crypto_4(key_0);

    crypto_2.set_shuffle(false);
    crypto_3.set_shuffle(false);
    crypto_4.set_shuffle(false);

    std::string d = "Hattı müdaafa yoktur, sathı müdafaa vardır. O satıh "
                    "bütün vatandır. Vatanın her karış toprağı, vatandaşın "
                    "kanıyla ıslanmadıkça, terke tabi değildir.";

    std::vector<char> data(d.begin(), d.end());

    crack(crypto_0, data);
    crack(crypto_1, data);
    crack(crypto_2, data);
    crack(crypto_3, data);
    crack(crypto_4, data);
}