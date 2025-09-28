// Copyright (c) 2025 Huzeyfe Çağılcı

#include "crypto.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

/* OpenMP library will be added later. */
#ifdef OMP
#include <omp.h>
#endif

using namespace std;
using namespace SimpleCrypto;

#define check_flag(x, y) (x & y) > 0

enum flags
{
    help = (1 << 1),
    key_from_file = (1 << 2),
    data_from_file = (1 << 3),
    verbose = (1 << 4),
    decrypt = (1 << 5)
};

struct param_stc
{
    unsigned int flags;

#ifdef OMP
    int threads;
#endif
    /*If key_from_file is false, then becomes key.*/
    string key_file;
    /*If data_from_file is false, then becomes data.*/
    string data_file;

    string out_file;
} params{0
#ifdef OMP
         ,
         8
#endif
};

void encrypt()
{
    Key *key;
    char *data;
    unsigned int size;

    if (check_flag(params.flags, key_from_file))
    {
        key = new Key(params.key_file);
    }
    else
    {
        _key_type_ ch;
        copy(params.key_file.begin(), params.key_file.end(), ch.begin());
        key = new Key(ch);
    }

    if (check_flag(params.flags, data_from_file))
    {
        fstream fs(params.data_file, ios::in | ios::binary);
        if (!fs.is_open())
        {
            cerr << "File Error" << endl;
            exit(-1);
        }

        fs.seekg(0, ios::end);
        size = fs.tellg();

        data = new char[size + 1];
        data[size] = '\0';

        fs.seekg(0, ios::beg);
        fs.read(data, size);
        fs.close();
    }
    else
    {
    }

    Crypto *cr = new Crypto0(*key);

    char *encrypted = cr->encrypt(data, size);

    fstream fs(params.out_file, ios::out | ios::binary);
    if (!fs.is_open())
    {
        cerr << "File Error" << endl;
        exit(-1);
    }

    fs.write(encrypted, size);
    fs.close();

    if (check_flag(params.flags, verbose))
    {
        cout << "Data: " << data << endl;
        cout << "Key: " << key->getKeyStr() << endl;
        cout << "Encrypted data writed to: " << params.out_file << endl;
    }

    delete encrypted;
    delete cr;
    delete key;
}

void print_help()
{
}

int main(int argc, char *argv[])
{
    for (auto i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0)
        {
            print_help();
        }
        else if (strcmp(argv[i], "--key-file") == 0)
        {
            if (argc >= ++i)
            {
                params.key_file = argv[i];
                params.flags |= key_from_file;
            }
            else
            {
                cerr << "Error: No argument after --key-file" << endl;
                exit(-1);
            }
        }
        else if (strcmp(argv[i], "--data-file") == 0)
        {
            if (argc >= ++i)
            {
                params.data_file = argv[i];
                params.flags |= data_from_file;

                params.out_file = params.data_file + ".sc";
            }
            else
            {
                cerr << "Error: No argument after --data-file" << endl;
            }
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
        {
            params.flags |= verbose;
        }
        else if (strcmp(argv[i], "--decrypt") == 0)
        {
            params.flags |= decrypt;
        }
    }

    if (check_flag(params.flags, verbose))
    {

#ifdef OMP
        cout << "OMP enabled." << endl;
#endif
        if (check_flag(params.flags, key_from_file))
        {
            cout << "Key File: " << params.key_file << endl;
        }

        if (check_flag(params.flags, data_from_file))
        {
            cout << "Data File: " << params.data_file << endl;
        }

        cout << "Out File: " << params.out_file << endl;
    }

    if (check_flag(params.flags, decrypt))
    {
        cout << "decrypt\n";
    }
    else
    {
        encrypt();
    }

    return 0;
}