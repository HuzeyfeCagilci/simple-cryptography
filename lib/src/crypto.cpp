// Copyright (c) 2025 Huzeyfe Çağılcı

/* Core file of Simple Cryptography library. */

#include "crypto.h"
#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <utility>

void printhex(std::vector<char> &data)
{
    int size = data.size();
    for (auto i = 0; i < size - (size % 2); i += 2)
    {
        unsigned int tmp = (((unsigned char)data[i]) << 16) | (unsigned char)data[i + 1];
        std::cout << std::hex << tmp;
        std::cout << ' ';
    }
    std::cout << std::dec;
}

_key_type_ hexTo(std::vector<char> hex)
{
    // ToDo:
    int size = hex.size();
    _key_type_ kt(size / 2, 0);
    int x = 16;

    for (int i = 0; i < size; i++)
    {
        if (hex[i] >= 'a' && hex[i] <= 'f')
        {
            kt[i / 2] += x * (hex[i] - 'a' + 10);
        }
        else if (hex[i] >= '0' && hex[i] <= '9')
        {
            kt[i / 2] += x * (hex[i] - '0');
        }

        x = x == 16 ? 1 : 16;
    }

    return kt;
}

namespace SimpleCrypto
{
Key::Key()
{
    size = 0;
}

Key::Key(_key_type_ &key)
{
    this->size = key.size();
    this->key = key;
}

Key::Key(const Key &other)
{
    this->size = other.size;
    this->key = other.key;
}

Key::Key(std::string filename)
{
    std::vector<char> hex;
    std::fstream fs(filename, std::ios::in);

    if (!fs.is_open())
    {
        std::cout << "File Error" << std::endl;
        exit(-1);
    }

    std::copy(std::istreambuf_iterator<char>(fs), {}, std::back_inserter(hex));
    key = hexTo(hex);
    size = key.size();

    fs.close();
}

std::string Key::getKeyStr()
{
    std::stringstream ss;
    for (auto i : key)
        ss << std::hex << (unsigned int)i;

    return std::string(ss.str());
}

Key &Key::operator=(const Key &other)
{
    if (this != &other)
    {
        size = other.size;
        key.reserve(size);
        std::copy(other.key.begin(), other.key.end(), key.begin());
    }
    return *this;
}

_key_type_ Key::getKey()
{
    _key_type_ keyCopy(key);
    return keyCopy;
}

int Key::getSize()
{
    return size;
};

void Key::printKey(std::string filename)
{
    std::fstream fs(filename, std::ios::out);
    if (!fs.is_open())
    {
        std::cout << "File Error" << std::endl;
        exit(-1);
    }

    fs << getKeyStr();
    fs.close();
}

Key generateKey(_size_type_ size)
{
    _key_type_ key_data(size);

    static std::seed_seq seed;
    static std::mt19937 generator{seed};

    std::uniform_int_distribution<unsigned char> dist(0, 255);
    for (auto &elem : key_data)
    {
        elem = dist(generator);
    }

    Key generatedKey(key_data);

    return generatedKey;
}

Key extendKey(Key key)
{
    int size = key.getSize();

    if (size < 3)
    {
        return key;
    }

    _key_type_ extended;
    _key_type_ keyV = key.getKey();

    for (int i = 0; i < size; i++)
    {
        for (int j = i + 1; j < size; j++)
        {
            unsigned char elm = keyV[i] ^ keyV[j];
            extended.push_back(elm);
        }
    }

    return Key(extended);
}

std::vector<char> Crypto::shuffle(std::vector<char> data, bool encryption)
{
    _key_type_ key_data = key.getKey();
    std::vector<char> shuffled(data);
    int size = key.getSize();
    int dataSize = data.size();

    if (encryption)
        for (auto j = 0; j < size; j++)
        {
            int idx = key_data[j] % dataSize;
            std::swap(shuffled[idx], shuffled[dataSize - idx - 1]);
        }
    else
        for (auto j = size - 1; j >= 0; j--)
        {
            int idx = key_data[j] % dataSize;
            std::swap(shuffled[idx], shuffled[dataSize - idx - 1]);
        }

    return shuffled;
}

/* Encrypts and mixes the data using the key.
   Since the mixing process is done according
   to the key, it can be reordered. */
std::vector<char> Crypto0::encrypt(std::vector<char> data)
{
    std::vector<char> encrypted_data(data);
    int size = key.getSize();
    int dataSize = data.size();
    _key_type_ key_data = key.getKey();

    for (auto i = 0; i < dataSize; i++)
    {
        for (auto j = 0; j < size; j++)
        {
            encrypted_data[i] = encrypted_data[i] ^ key_data[j];
        }
    }

    if (do_shuffle)
        encrypted_data = shuffle(encrypted_data, true);

    return encrypted_data;
}

/* Reorders and decrypts the data using the key. */
std::vector<char> Crypto0::decrypt(std::vector<char> encrypted_data)
{

    std::vector<char> decrypted_data(encrypted_data);
    int size = key.getSize();
    int dataSize = decrypted_data.size();
    _key_type_ key_data = key.getKey();

    if (do_shuffle)
        decrypted_data = shuffle(decrypted_data, false);

    for (auto i = 0; i < dataSize; i++)
    {
        for (auto j = 0; j < size; j++)
        {
            decrypted_data[i] = decrypted_data[i] ^ key_data[j];
        }
    }

    return decrypted_data;
}

std::vector<char> Crypto1::encrypt(std::vector<char> data)
{
    std::vector<char> encrypted_data(data);
    int size = key.getSize();
    int dataSize = data.size();
    _key_type_ key_data = key.getKey();

    for (auto i = 0; i < dataSize; i++)
    {
        encrypted_data[i] = data[i] ^ key_data[i % size];
    }
    return encrypted_data;
}

std::vector<char> Crypto1::decrypt(std::vector<char> data)
{
    return encrypt(data);
}

} // namespace SimpleCrypto