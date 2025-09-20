// Copyright (c) 2025 Huzeyfe Çağılcı

/* A test to write the key to the file
   and read it from the file. */

#include <iostream>

#include "crypto.h"

using namespace SimpleCrypto;

#define filename "test1.sckey"

int main()
{
    std::cout << "Test 1" << std::endl;

    Key key = generateKey(4);
    std::cout << "Key:" << std::endl << key.getKeyStr() << std::endl;

    key.printKey(std::string(filename));

    Key key_(filename);
    std::cout << "Key_:" << std::endl << key.getKeyStr() << std::endl;
}