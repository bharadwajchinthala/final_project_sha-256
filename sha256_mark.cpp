#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdint>  // For uint32_t and uint64_t types

using namespace std;

// Use shorter type names for clarity
typedef uint32_t uint32;
typedef uint64_t uint64;

// Rotate bits right
#define ROTATE_RIGHT(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))

// SHA-256 helper functions
uint32 selectBits(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (~x & z); }
uint32 majorityBits(uint32 x, uint32 y, uint32 z) { return (x & y) ^ (x & z) ^ (y & z); }

uint32 upperSigma0(uint32 x) { return ROTATE_RIGHT(x, 2) ^ ROTATE_RIGHT(x, 13) ^ ROTATE_RIGHT(x, 22); }
uint32 upperSigma1(uint32 x) { return ROTATE_RIGHT(x, 6) ^ ROTATE_RIGHT(x, 11) ^ ROTATE_RIGHT(x, 25); }
uint32 lowerSigma0(uint32 x) { return ROTATE_RIGHT(x, 7) ^ ROTATE_RIGHT(x, 18) ^ (x >> 3); }
uint32 lowerSigma1(uint32 x) { return ROTATE_RIGHT(x, 17) ^ ROTATE_RIGHT(x, 19) ^ (x >> 10); }

// Predefined round constants for SHA-256
const uint32 constantValues[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Initial hash values
uint32 baseHash[8] = {
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
};

// Function to add padding and length information
vector<unsigned char> addPadding(const vector<unsigned char>& dataBytes) {
    vector<unsigned char> paddedData = dataBytes;

    // Append '1' bit (0x80 in hex)
    paddedData.push_back(0x80);

    // Add zero bytes until message length is 56 mod 64
    while (paddedData.size() % 64 != 56)
        paddedData.push_back(0x00);

    // Append 64-bit message length (in bits)
    uint64 totalBits = (uint64)dataBytes.size() * 8;
    for (int i = 7; i >= 0; i--)
        paddedData.push_back((totalBits >> (i * 8)) & 0xFF);

    return paddedData;
}

// Core SHA-256 computation
void performSHA256(const vector<unsigned char>& messageBytes, uint32 finalHash[8]) {
    vector<unsigned char> paddedData = addPadding(messageBytes);

    for (size_t i = 0; i < paddedData.size(); i += 64) {
        uint32 messageWords[64];

        // Convert 512-bit block into 16 32-bit words
        for (int j = 0; j < 16; j++) {
            messageWords[j] = (paddedData[i + 4 * j] << 24) |
                              (paddedData[i + 4 * j + 1] << 16) |
                              (paddedData[i + 4 * j + 2] << 8) |
                              (paddedData[i + 4 * j + 3]);
        }

        // Extend to 64 words using σ0 and σ1 functions
        for (int j = 16; j < 64; j++) {
            messageWords[j] = lowerSigma1(messageWords[j - 2]) +
                              messageWords[j - 7] +
                              lowerSigma0(messageWords[j - 15]) +
                              messageWords[j - 16];
        }

        // Initialize working variables
        uint32 regA = finalHash[0];
        uint32 regB = finalHash[1];
        uint32 regC = finalHash[2];
        uint32 regD = finalHash[3];
        uint32 regE = finalHash[4];
        uint32 regF = finalHash[5];
        uint32 regG = finalHash[6];
        uint32 regH = finalHash[7];

        // Compression loop (64 rounds)
        for (int j = 0; j < 64; j++) {
            uint32 temp1 = regH + upperSigma1(regE) + selectBits(regE, regF, regG) + constantValues[j] + messageWords[j];
            uint32 temp2 = upperSigma0(regA) + majorityBits(regA, regB, regC);

            regH = regG;
            regG = regF;
            regF = regE;
            regE = regD + temp1;
            regD = regC;
            regC = regB;
            regB = regA;
            regA = temp1 + temp2;
        }

        // Add this block's hash to the result
        finalHash[0] += regA;
        finalHash[1] += regB;
        finalHash[2] += regC;
        finalHash[3] += regD;
        finalHash[4] += regE;
        finalHash[5] += regF;
        finalHash[6] += regG;
        finalHash[7] += regH;
    }
}

int main() {
    // Open the file containing the Book of Mark
    ifstream textFile("mark.txt", ios::binary);
    if (!textFile.is_open()) {
        cerr << "Error: Could not open mark.txt" << endl;
        return 1;
    }

    // Read file contents
    vector<unsigned char> bookData((istreambuf_iterator<char>(textFile)), istreambuf_iterator<char>());
    textFile.close();

    // Initialize hash with default constants
    uint32 outputHash[8];
    memcpy(outputHash, baseHash, sizeof(baseHash));

    // Process the SHA-256 algorithm
    performSHA256(bookData, outputHash);

    // Print final 256-bit hash
    cout << "SHA-256 hash for Book of Mark:\n";
    for (int i = 0; i < 8; i++) {
        cout << hex << setw(8) << setfill('0') << outputHash[i];
    }
    cout << endl;

    return 0;
}

