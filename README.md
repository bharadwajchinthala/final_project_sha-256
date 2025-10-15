# final_project_sha-256
# SHA-256 Implementation – Book of Mark Project

## Project Overview
This project provides a **C++ implementation of the SHA-256 algorithm**, created entirely from scratch using only standard C++ headers.  
The program reads the **Book of Mark** text from a file named `mark.txt`, processes the full content through the SHA-256 algorithm, and prints the resulting **256-bit hash** in hexadecimal format.

The algorithm follows the official pseudocode from [Wikipedia: SHA-2](https://en.wikipedia.org/wiki/SHA-2) and demonstrates core hashing concepts such as message padding, bitwise operations, and block compression.

---

## Features
- 100% C++ standard implementation (no external libraries)  
- Proper handling of padding and bit length encoding  
- Accurate 64-round compression loop  
- Processes large text files efficiently  
- Clean and readable variable names  
- Simple comments for easy understanding  

---

---

##  Compilation and Execution

### Step 1: Compile the program
Use any modern C++ compiler such as `g++`:
```bash
g++ sha256_mark.cpp -o sha256_mark

Step 2: Run the program

Make sure mark.txt is in the same directory:

./sha256_mark


The program will output the SHA-256 hash of the entire file.

## Output
SHA-256 hash for Book of Mark:
1a7c13f24658ef7d55c2bfb2af4f95b9baf67b84eeb5a9ec5e593e49c8a07d9d



##How the Algorithm Works

Read the message – The entire file content is read as bytes.

Padding – A 1 bit (0x80) is added, followed by zeros until the message length is 56 bytes modulo 64.

Append Length – The message length (in bits) is added as a 64-bit big-endian integer.

Divide into Blocks – The padded message is split into 512-bit chunks.

Message Schedule Expansion – Each block is expanded into 64 32-bit words.

Main Compression Loop – The words are processed in 64 rounds using logical and bitwise operations with fixed constants.

Hash Combina

