# DATA PRIVACY IN CLOUD COMPUTING

## Description
This repo contains the documents and code for the Thesis of ***Pham Ha Minh Thy - ITITIU19056***.
The purpose of this thesis is to build a secure file sharing system based on the method of Revocable-Storage Identity-Based Encryption (RS-IBE). In this system, the RS-IBE scheme is applied for key encryption only. For file encryption, the system uses SHA-256 and AES.

## Authors Information
|Role   |Name   |Email  |
|-------|-------|-------|
|Student    |Pham Ha Minh Thy   |ititiu19056@student.hcmiu.edu.vn   |
|Instructor |Le Hai Duong   |lhduong@hcmiu.edu.vn   |

## Folder Structure
- `code/`: contains the C code.
    - `input.txt`: a plaintext file that will be encrypted.
    - `rs-ibe.c`: the system's code.
- `docs/`: contains relevant documents.
- `pbc-0.5.14/`: Pairing-Based Cryptography library version 0.5.14 used for RS-IBE.
- `README.md`: README file.
- `.gitignore`: Gitignore file.

## Instruction
First, make sure we have a plaintext file `input.txt`.

To compile the code, open the terminal and run the below commands:
```
gcc -c rs-ibe.c -o rs-ibe.o
gcc rs-ibe.o ../pbc-0.5.14/misc/*.o -L. -lgmp -lpbc -lssl -lcrypto
./a.out
```
The system will ask to enter `time 1`, `time 2` and `receiver`. Please enter the values in **binary** format.
For example, the file is encrypted for user with ID 100 at time t1 011 and then decrypted at time t2 101 (note: t2 >= t1):
```
time 1: 011
time 2: 101
receiver: 100
```

To add a user to the revocation list, use `Revoke()` function.
For example:
```
Revoke(revokedList, "001");
```

If the time and user ID are valid, the system automatically generates a ciphertext file `encrypted_output.enc` and a decrypted file `decrypted_output.txt` after decryption.