# inshack-2017-cryptor
INSHACK CTF 2017 - Crypt0r Challenge source code

## Challenges

### Part 1. [Forensic] [Easy]
One of our HR opened a mail attachment and got her files encrypted. Could you have a look at her emails and find what's wrong?

### Part 2. [Reverse] [Intermediate]
Something tagged as debug cannot be dangerous. How would you make your tests if it harms your data?

### Part 3. [Crypto] [Hard]
Are you smart enough to decrypt this file?

## Code structure

### Command & Control

The C&C hit by the malware once it is ran. No big deal.

### Downloader

The javascript payload that the teams had to find in the first part of the challenge to get the flag. An email was hidden in a tons of other messages containing this payload.

The directory contains a tool to obfuscate automatically the payload.

### Tools

The tools, or the only tool, is the strings appender. Actually, the binary did not contain any string. Instead, they were encrypted then appended to the binary. At the end, the real size of the binary was append so when the binary was reading its strings at the runtime, it was able to start reading at the right offset.

The `encoder` tool depends on the strings contained in `rsrc` and the cryptor binary.

### Source

The Crypt0r's sources are stored in the `src` directory. It aims at recoding the way a private key is generated in order to accept a seed. This seed is totally weak since it is based on the current timestamp.

## Build the code

To build the code, you can run the `make` command.
