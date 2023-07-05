#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "modes.h"
#include "aes.h"
#include "des.h"
#include <iostream>

// Time in seconds to run each benchmark
const double runTimeInSeconds = 3.0;

// CPU frequency in Hz
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

// Function to run the benchmark for a given cipher and RNG
void runBenchmarkDecryption(CryptoPP::StreamTransformation& cipher, CryptoPP::AutoSeededRandomPool& prng)
{
    // Determine buffer size, rounding up to optimal block size
    const int BUF_SIZE = CryptoPP::RoundUpToMultipleOf(2048U,
        dynamic_cast<CryptoPP::StreamTransformation&>(cipher).OptimalBlockSize());

    // Generate a random buffer of the appropriate size
    CryptoPP::AlignedSecByteBlock buf(BUF_SIZE);
    CryptoPP::AlignedSecByteBlock recovered(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    // Encrypt the data once to warm up the cache
    cipher.ProcessString(buf, BUF_SIZE);

    // Initialize loop variables
    double elapsedTimeInSeconds = 0.0;
    unsigned long i = 0, blocks = 1;

    // Start the timer
    CryptoPP::ThreadUserTimer timer;
    timer.StartTimer();

    // Continue doubling the block count until the elapsed time exceeds the target runtime
    do
    {
        blocks *= 2;
        for (; i < blocks; i++)
            cipher.ProcessString(recovered, buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    } while (elapsedTimeInSeconds < runTimeInSeconds);

    // Compute and output benchmark results
    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << cipher.AlgorithmName() << " decryption benchmarks..." << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    std::cout << std::endl;
}

int main(int argc, char* argv[])
{
    // Initialize the RNG
    CryptoPP::AutoSeededRandomPool prng;

    // Benchmark DES decryption
    CryptoPP::SecByteBlock desKey(CryptoPP::DES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(desKey, desKey.size());

    CryptoPP::CTR_Mode<CryptoPP::DES>::Encryption desCipherEnc;
    desCipherEnc.SetKeyWithIV(desKey, desKey.size(), desKey);
    CryptoPP::CTR_Mode<CryptoPP::DES>::Decryption desCipherDec;
    desCipherDec.SetKeyWithIV(desKey, desKey.size(), desKey);

    // Warm up cache with initial encryption
    desCipherEnc.ProcessString(desKey, desKey.size());

    runBenchmarkDecryption(desCipherDec, prng);

    // Benchmark AES decryption
    CryptoPP::SecByteBlock aesKey(CryptoPP::AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(aesKey, aesKey.size());

    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption aesCipherEnc;
    aesCipherEnc.SetKeyWithIV(aesKey, aesKey.size(), aesKey);
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption aesCipherDec;
    aesCipherDec.SetKeyWithIV(aesKey, aesKey.size(), aesKey);

    // Warm up cache with initial encryption
    aesCipherEnc.ProcessString(aesKey, aesKey.size());

    runBenchmarkDecryption(aesCipherDec, prng);

    system("pause");
    return 0;
}
