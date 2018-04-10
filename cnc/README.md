# Cryptor - C&C

The Command & Control of the Cryptor challenge. The code is quite dirty.

The protocol is a pseudo-encrypted HTTP:
- Clear HTTP headers
- Multiple `xor` layers to encrypt the payload
