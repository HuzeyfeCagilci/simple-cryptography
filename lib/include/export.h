#pragma once

#if defined(_WIN32) || defined(_WIN64)
#ifdef SIMPLECRYPTO_EXPORTS
#define SIMPLECRYPTO_API __declspec(dllexport)
#else
#define SIMPLECRYPTO_API __declspec(dllimport)
#endif
#else
#define SIMPLECRYPTO_API
#endif
