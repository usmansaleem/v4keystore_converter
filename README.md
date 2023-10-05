# BLS v4 Keystore converter

Converts v4 keystore's kdf function parameters. 

This program reads v4 formatted `.json` files from a directory and either a single password file or
matching password file names ending in `.txt` from a directory and converts the kdf function to either
PBKDF2 or SCRYPT. The v4 keystore generated by other tools is typically using SCRYPT with cpu cost parameter `n=262144` 
which makes it very secure but very expensive to compute. By decreasing `n` parameter in SCRYPT or `c` parameter in PBKDF2,
the decryption time can be decreased drastically.

The encryption/decryption code is based on [Teku](https://github.com/Consensys/teku/tree/master/infrastructure/bls-keystore)

## Build:
- Download library dependencies
```sh
./bld download
```
- Compile
```sh
./bld compile
```

- Run
```sh
./bld run
```

Assuming that existing keys are in directory `keys`, and password is to be read from `password.txt`,
to convert to PBKDF2 with iteration count `c` of 10, the usage would be:
```sh
mkdir ./pbkdf2
./bld run --src=./keys --dest=./pbkdf2 -password-path=./password.txt --kdf-function=PBKDF2 -c=10 
```