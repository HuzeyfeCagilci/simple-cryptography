// Copyright (c) 2025 Huzeyfe Çağılcı

#ifndef __CRYPTO_H__
#define __CRYPTO_H__

#include "export.h"
#include <string>
#include <vector>

#define _key_type_ std::vector<unsigned char>
#define _size_type_ unsigned char

SIMPLECRYPTO_API void printhex(const char *data, int size);

namespace SimpleCrypto
{

class SIMPLECRYPTO_API Key
{
  private:
    _key_type_ key;
    _size_type_ size;

  public:
    Key(_key_type_ &key, _size_type_ size);
    Key(const Key &other);
    Key(std::string filename);

    ~Key() {};

    Key &operator=(const Key &other);

    std::string getKeyStr();
    _key_type_ getKey();
    int getSize();
    void printKey(std::string filename);
};

SIMPLECRYPTO_API Key generateKey(_size_type_ size);

class SIMPLECRYPTO_API Crypto
{
  protected:
    Key key;

  public:
    Crypto(Key key) : key(key) {};
    virtual ~Crypto() {};

    virtual char *encrypt(const char *data, unsigned int dataSize) = 0;
    virtual char *decrypt(const char *encrypted_data, unsigned int dataSize) = 0;
};

class SIMPLECRYPTO_API Crypto0 : public Crypto
{
  public:
    Crypto0(Key key) : Crypto(key) {};

    char *encrypt(const char *data, unsigned int dataSize) override;
    char *decrypt(const char *encrypted_data, unsigned int dataSize) override;
};

} // namespace SimpleCrypto
#endif // __CRYPTO_H__