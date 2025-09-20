// Copyright (c) 2025 Huzeyfe Çağılcı

/* Core file of Simple Cryptography library. */

#include "crypto.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>

void printhex(const char *data, int size)
{
    for (auto i = 0; i < size; i++)
    {
        std::cout << std::hex << (unsigned int)(unsigned char)data[i];
        if ((i + 1) % 4 == 0)
            std::cout << ' ';
    }
}

namespace SimpleCrypto
{

Key::Key(_key_type_ &key, _size_type_ size)
{
    this->size = size;
    this->key = key;
}

Key::Key(const Key &other)
{
    this->size = other.size;
    this->key = other.key;
}

Key::Key(std::string filename)
{
    std::fstream fs(filename, std::ios::hex | std::ios::in);
    if (!fs.is_open())
    {
        std::cout << "File Error" << std::endl;
        exit(-1);
    }

    fs.seekg(0, std::ios::end);
    size = (_size_type_)fs.tellg();
    fs.seekg(0, std::ios::beg);

    key.reserve(size);

    char *ch = new char[size];

    fs.read(ch, size);
    key.reserve(size);
    std::copy(ch, ch + size, key.begin());

    fs.close();
    delete[] ch;
}

std::string Key::getKeyStr()
{
    std::stringstream ss;
    // char *keyStr = new char[size * 2 + 1];
    for (auto i : key)
        ss << std::hex << (unsigned int)i;

    // delete[] keyStr;
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

    std::seed_seq seed{time(0)};
    std::mt19937 generator(seed);

    std::uniform_int_distribution<unsigned char> dist(0, 255);
    for (auto &elem : key_data)
    {
        elem = dist(generator);
    }

    Key generatedKey(key_data, size);

    return generatedKey;
}

/* Encrypts and mixes the data using the key.
   Since the mixing process is done according
   to the key, it can be reordered. */
char *Crypto0::encrypt(const char *data, unsigned int dataSize)
{
    char tmp;
    char *encrypted_data = new char[dataSize];
    int size = key.getSize();
    _key_type_ key_data = key.getKey();

    std::copy(data, data + dataSize, encrypted_data);

    for (auto i = 0; i < dataSize; i++)
    {
        for (auto j = 0; j < size; j++)
        {
            encrypted_data[i] = encrypted_data[i] ^ key_data[j];
        }
    }

    for (auto j = 0; j < size; j++)
    {
        int idx = key_data[j] % dataSize;
        tmp = encrypted_data[idx];
        encrypted_data[idx] = encrypted_data[dataSize - idx - 1];
        encrypted_data[dataSize - idx - 1] = tmp;
    }

    return encrypted_data;
}

/* Reorders and decrypts the data using the key. */
char *Crypto0::decrypt(const char *encrypted_data, unsigned int dataSize)
{
    char tmp;
    char *decrypted_data = new char[dataSize];
    int size = key.getSize();
    _key_type_ key_data = key.getKey();

    std::copy(encrypted_data, encrypted_data + dataSize, decrypted_data);

    for (auto j = size - 1; j >= 0; j--)
    {
        int idx = key_data[j] % dataSize;
        tmp = decrypted_data[idx];
        decrypted_data[idx] = decrypted_data[dataSize - idx - 1];
        decrypted_data[dataSize - idx - 1] = tmp;
    }

    for (auto i = 0; i < dataSize; i++)
    {
        for (auto j = 0; j < size; j++)
        {
            decrypted_data[i] = decrypted_data[i] ^ key_data[j];
        }
    }

    return decrypted_data;
}
} // namespace SimpleCrypto