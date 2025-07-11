# CryptoTerm File Encryption Tool

A client-side file encryption tool supporting AES and rc6 algorithms with large file handling capabilities through intelligent file segmentation.

## Features

- 🔐 **Multiple Encryption Algorithms**: Support for AES-256-CBC and RC6
- 📦 **Large File Support**: Efficient handling of large files through chunked processing
- 🔑 **Flexible Key Management**: 
  - Auto-generate secure keys
  - Password-based key derivation (PBKDF2)
  - Direct key input support
- 🚀 **Memory Efficient**: Process files of any size without loading them entirely into memory
- 🛡️ **Security Features**:
  - Unique IV for each chunk
  - Salt for password-based encryption
  - Cryptographically secure random number generation
- 📁 **Single File Output**: Despite segmentation, produces a single encrypted file

- OOP implementation provides:

1. **Robust Architecture**: Clean class hierarchy with single responsibility principle
2. **Large File Support**: Efficient chunked processing without memory constraints
3. **Security**: Unique IV per chunk, proper key derivation, and metadata protection
4. **Flexibility**: Configurable chunk sizes and multiple encryption options
5. **User-Friendly**: Clear error messages and progress indication
6. **Maintainable**: Well-documented code with clear separation of concerns

- The application handles files of any size efficiently while maintaining security and producing a single encrypted output file.
## Installation

### Prerequisites

- Python 3.9 or higher
- pip package manager

### Install Dependencies

```bash

git clone <repository-url>
cd file-encryption-tool


pip install pycryptodome


pip install RC6Encryption
```
## How to use?
```bash
cryptoterm encrypt -a aes <-k "YourBase64EncodedKey="> video.mp4
```
```bash
cryptoterm decrypt -a aes -k "YourBase64EncodedKey=" video_aes.enc.mp4
```
Chunked encryption (default chunk size is 1MB you can change to 10MB!)
```bash 
cryptotem encrypt -a aes -c 10 huge_file.zip

```
## Architecture

### Object-Oriented Design

Cryptoterm follows OOP principles with clear separation of concerns:

    - KeyManager: Handles key generation and derivation
    - FileHandler: Manages file I/O with chunking support
    - CipherBase: Abstract base class for cipher implementations
    - AESCipher/RC6Cipher: Concrete cipher implementations
    - CipherFactory: Factory pattern for cipher creation
    - FileEncryptor: Main encryption/decryption logic
    - CLIHandler: Command-line interface management
    - Application: Main application orchestrator

Encrypted files have the following structure:
```bash
[Metadata (45 bytes)] [Encrypted Chunk 1] [Encrypted Chunk 2] ... [Encrypted Chunk N]
```

# ⚠️Caution
- Increase chunk size for better performance: -c 10
- Always ensure sufficient disk space for output file
- Use the same algorithm for decryption as was used for encryption
- if you need to use your own key ensure the key is properly base64 encoded and length is 32Bytes

# Author/Developer
This application is written by [a Amir Ahmadabadiha](https://linkedin.com/in/amir-ahmadabadiha-259113175) the Founder of [a Filesaver](https://filesaver.ir/) Platform
Contact Mail | Bug Report:  
## License
This project is licensed under the [GNU General Public License v3.0](https://www.gnu.org/licenses/gpl-3.0.html).  
See the [LICENSE](./LICENSE) file for details.