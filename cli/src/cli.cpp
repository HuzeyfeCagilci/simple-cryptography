// Copyright (c) 2025 Huzeyfe Çağılcı

#include "crypto.h"
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

/* OpenMP library will be added later. */
#ifdef OMP
#include <omp.h>
#endif

using namespace std;
using namespace SimpleCrypto;

#define check_flag(x, y) (((x) & (y)) != 0)

enum flags
{
    help = (1 << 0),
    key_from_file = (1 << 1),
    data_from_file = (1 << 2),
    out_to_file = (1 << 3),
    verbose = (1 << 4),
    encrypt = (1 << 5),
    decrypt = (1 << 6)
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
} params{0, "", "", ""
#ifdef OMP
         ,
         8
#endif
};

void encrypt_()
{
    Key *key;
    vector<char> data;
    int size;

    if (check_flag(params.flags, key_from_file))
    {
        key = new Key(params.key_file);
    }
    else
    {
        auto ch = hexTo(vector<char>(params.key_file.begin(), params.key_file.end()));
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

        std::copy(std::istreambuf_iterator<char>(fs), {}, std::back_inserter(data));
    }
    else
    {
        std::copy(params.data_file.begin(), params.data_file.end(), std::back_inserter(data));
    }

    Crypto *cr = new Crypto0(*key);
    auto encrypted = cr->encrypt(data);
    size = encrypted.size();

    if (params.out_file == "")
    {
        for (int i = 0; i < size; i++)
        {
            cout << hex << (unsigned int)encrypted[i];
        }
        cout << dec << endl;
    }
    else
    {
        fstream fs(params.out_file, ios::out | ios::binary);
        if (!fs.is_open())
        {
            cerr << "File Error" << endl;
            exit(-1);
        }

        std::copy(encrypted.begin(), encrypted.end(), std::ostreambuf_iterator<char>(fs));
        fs.close();
    }

    if (check_flag(params.flags, verbose))
    {
        cout.write(data.data(), data.size());
        cout << endl << "Key: " << key->getKeyStr() << endl;
        cout << "Encrypted data writed to: " << params.out_file << endl;
    }

    delete cr;
    delete key;
}

void decrypt_()
{
    Key *key;
    vector<char> data;
    int size;

    if (check_flag(params.flags, key_from_file))
    {
        key = new Key(params.key_file);
    }
    else
    {
        auto ch = hexTo(vector<char>(params.key_file.begin(), params.key_file.end()));
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

        std::copy(std::istreambuf_iterator<char>(fs), {}, std::back_inserter(data));
    }
    else
    {
        std::copy(params.data_file.begin(), params.data_file.end(), std::back_inserter(data));
    }

    Crypto *cr = new Crypto0(*key);
    auto decrypted = cr->decrypt(data);
    size = decrypted.size();

    if (params.out_file == "")
    {
        for (int i = 0; i < size; i++)
        {
            cout << decrypted[i];
        }
        cout << endl;
    }
    else
    {
        fstream fs(params.out_file, ios::out | ios::binary);
        if (!fs.is_open())
        {
            cerr << "File Error" << endl;
            exit(-1);
        }

        std::copy(decrypted.begin(), decrypted.end(), std::ostreambuf_iterator<char>(fs));
        fs.close();
    }

    if (check_flag(params.flags, verbose))
    {
        cout.write(decrypted.data(), decrypted.size());
        cout << endl << "Key: " << key->getKeyStr() << endl;
        cout << "Decrypted data writed to: " << params.out_file << endl;
    }

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
            if (argc > ++i)
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
        else if (strcmp(argv[i], "--key") == 0)
        {
            if (argc > ++i)
            {
                params.flags &= ~key_from_file;
                params.key_file = argv[i];
            }
            else
            {
                cerr << "Error: No argument after --key" << endl;
            }
        }
        else if (strcmp(argv[i], "--data-file") == 0)
        {
            if (argc > ++i)
            {
                params.data_file = argv[i];
                params.flags |= data_from_file;
            }
            else
            {
                cerr << "Error: No argument after --data-file" << endl;
            }
        }
        else if (strcmp(argv[i], "--data") == 0)
        {
            if (argc > ++i)
            {
                params.flags &= ~data_from_file;
                params.data_file = argv[i];
            }
            else
            {
                cerr << "Error: No argument after --data" << endl;
            }
        }
        else if (strcmp(argv[i], "--out-file") == 0)
        {
            if (argc > ++i)
            {
                params.flags |= out_to_file;
                params.out_file = argv[i];
            }
            else
            {
                cerr << "Error: No argument after --data" << endl;
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
        else if (strcmp(argv[i], "--encrypt") == 0)
        {
            params.flags |= encrypt;
        }
        else
        {
            cout << "Unknown parameter: " << argv[i] << endl;
        }
    }

    if (check_flag(params.flags, verbose))
    {

#ifdef OMP
        cout << "OMP enabled." << endl;
#endif
        if (check_flag(params.flags, key_from_file))
            cout << "Key File: " << params.key_file << endl;

        if (check_flag(params.flags, data_from_file))
            cout << "Data File: " << params.data_file << endl;

        if (check_flag(params.flags, out_to_file))
            cout << "Out File: " << params.out_file << endl;
    }

    if (check_flag(params.flags, decrypt))
    {
        decrypt_();
    }
    else if (check_flag(params.flags, encrypt))
    {
        encrypt_();
    }

    return 0;
}