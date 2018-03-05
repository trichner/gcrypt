# Gcrypt Password String Encryption

This tool and the `cryptor` package implement a simple and secure scheme
to provide **confidentiality** and **integrity** for password encrypted key/value strings.

It is compatible with the java implementation found here: https://github.com/trichner/tcrypt

## Build Instructions

```
~> go build
```

## Usage

```
# Encryption
~> gcrypt enc <property key> <filename>
# Decryption
~> gcrypt dec <property key> <filename>
```

## Encryption

The underlying encryption scheme builds ontop of AES-GCM128 with an initialisation vector (IV/nonce) of
12 random bytes. The key for AES-GCM is derived with PBKDF2 and lots of iterations.
In order to allow upgrading ciphers/scheme at some point a version byte is
prepended to the encrypted message.

All ciphertext data including nonce and version byte are part of the message tag in order to provide integrity.

A ciphertext message has the following structure:
```
        +-------------------------------------------------------------------+
        |         |               |                             |           |
        | version | IV bytes      | ciphertext bytes            |    tag    |
        |  0x01   |               |                             |           |
        +-------------------------------------------------------------------+
Length:     1B        12B            len(plaintext) bytes            16B
```

## Limitations

- Message sizes for AES-GCM should be limited to 2^39-256 bits ~ 64 GB. Altough this implementation will run out of memory way earlier ;)
- Do not encrypt more than 2^32 messages with the same key as the risk of a nonce repeating becomes greater and greater. A nonce re-use is disastrous in case of AES-GCM.
- The AES key is limited to 128bit due to limitations in the default Java JCE.