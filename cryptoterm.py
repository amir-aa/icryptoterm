#!/usr/bin/env python3

import os
import sys
import argparse
import hashlib
import secrets
import struct
from pathlib import Path
from typing import Optional, Tuple, BinaryIO, Iterator
from abc import ABC, abstractmethod
from dataclasses import dataclass
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


try:
    from RC6Encryption import RC6Encryption
    RC6_AVAILABLE = True
except ImportError:
    RC6_AVAILABLE = False
    print("Warning: RC6Encryption not available. Install it with: pip install RC6Encryption")


# Constants
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for large file handling
AES_BLOCK_SIZE = 16
RC6_BLOCK_SIZE = 16
DEFAULT_KEY_SIZE = 32  # 256 bits
SALT_SIZE = 16
ITERATION_COUNT = 100000
METADATA_SIZE = 32  # For storing file metadata


@dataclass
class EncryptionMetadata:
    """Metadata for encrypted files."""
    algorithm: str
    salt: bytes
    iv: bytes
    original_size: int
    chunk_count: int
    
    def to_bytes(self) -> bytes:
        """Serialize metadata to bytes."""
        algo_byte = b'A' if self.algorithm == 'aes' else b'R'
        return (
            algo_byte +
            self.salt +
            self.iv +
            struct.pack('>Q', self.original_size) +
            struct.pack('>I', self.chunk_count)
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptionMetadata':
        """Deserialize metadata from bytes."""
        algo = 'aes' if data[0:1] == b'A' else 'rc6'
        salt = data[1:17]
        iv = data[17:33]
        original_size = struct.unpack('>Q', data[33:41])[0]
        chunk_count = struct.unpack('>I', data[41:45])[0]
        return cls(algo, salt, iv, original_size, chunk_count)


class KeyManager:
    """Manages encryption keys and their generation."""
    
    @staticmethod
    def generate_random_key(size: int = DEFAULT_KEY_SIZE) -> bytes:
        """Generate a cryptographically secure random key."""
        return secrets.token_bytes(size)
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes, 
                                key_size: int = DEFAULT_KEY_SIZE) -> bytes:
        """Derive a key from password using PBKDF2."""
        return hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode(), 
            salt, 
            ITERATION_COUNT, 
            dklen=key_size
        )
    
    @staticmethod
    def encode_key(key: bytes) -> str:
        """Encode binary key to base64 string."""
        return base64.b64encode(key).decode()
    
    @staticmethod
    def decode_key(key_str: str) -> bytes:
        """Decode base64 string to binary key."""
        return base64.b64decode(key_str.encode())


class FileHandler:
    """Handles file operations with chunking support."""
    
    def __init__(self, chunk_size: int = CHUNK_SIZE):
        self.chunk_size = chunk_size
    
    def read_chunks(self, file_path: Path) -> Iterator[Tuple[int, bytes]]:
        """Read file in chunks with chunk index."""
        with open(file_path, 'rb') as f:
            chunk_index = 0
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                yield chunk_index, chunk
                chunk_index += 1
    
    def write_chunks(self, file_handle: BinaryIO, chunks: Iterator[bytes]) -> None:
        """Write chunks to file."""
        for chunk in chunks:
            file_handle.write(chunk)
    
    def get_file_size(self, file_path: Path) -> int:
        """Get file size in bytes."""
        return file_path.stat().st_size
    
    def calculate_chunk_count(self, file_size: int) -> int:
        """Calculate number of chunks for given file size."""
        return (file_size + self.chunk_size - 1) // self.chunk_size


class CipherBase(ABC):
    """Abstract base class for cipher implementations."""
    
    def __init__(self, key: bytes):
        self.key = key
        self.block_size = self.get_block_size()
    
    @abstractmethod
    def get_block_size(self) -> int:
        """Get cipher block size."""
        pass
    
    @abstractmethod
    def encrypt_chunk(self, chunk: bytes, iv: bytes, chunk_index: int) -> bytes:
        """Encrypt a single chunk."""
        pass
    
    @abstractmethod
    def decrypt_chunk(self, chunk: bytes, iv: bytes, chunk_index: int, is_last: bool = False) -> bytes:
        """Decrypt a single chunk."""
        pass
    
    def _get_chunk_iv(self, base_iv: bytes, chunk_index: int) -> bytes:
        """Generate unique IV for each chunk based on chunk index."""
        # XOR the base IV with chunk index to ensure unique IVs
        iv_int = int.from_bytes(base_iv, 'big')
        iv_int ^= chunk_index
        return iv_int.to_bytes(len(base_iv), 'big')


class AESCipher(CipherBase):
    """AES cipher implementation."""
    
    def get_block_size(self) -> int:
        return AES_BLOCK_SIZE
    
    def encrypt_chunk(self, chunk: bytes, iv: bytes, chunk_index: int) -> bytes:
        """Encrypt chunk using AES-CBC."""
        chunk_iv = self._get_chunk_iv(iv, chunk_index)
        cipher = AES.new(self.key, AES.MODE_CBC, chunk_iv)
        padded_chunk = pad(chunk, self.block_size)
        return cipher.encrypt(padded_chunk)
    
    def decrypt_chunk(self, chunk: bytes, iv: bytes, chunk_index: int, is_last: bool = False) -> bytes:
        """Decrypt chunk using AES-CBC."""
        chunk_iv = self._get_chunk_iv(iv, chunk_index)
        cipher = AES.new(self.key, AES.MODE_CBC, chunk_iv)
        padded_plaintext = cipher.decrypt(chunk)
        if is_last:
            return unpad(padded_plaintext, self.block_size)
        return padded_plaintext


class RC6Cipher(CipherBase):
    """RC6 cipher implementation using RC6Encryption library."""
    
    def __init__(self, key: bytes):
        if not RC6_AVAILABLE:
            raise RuntimeError("RC6Encryption module not available")
        super().__init__(key)
        # RC6Encryption expects key as hex string
        self.rc6_key = key.hex()
    
    def get_block_size(self) -> int:
        return RC6_BLOCK_SIZE
    
    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """XOR two byte arrays."""
        return bytes(x ^ y for x, y in zip(a, b))
    
    def _cbc_encrypt(self, data: bytes, iv: bytes) -> bytes:
        """Implement CBC mode encryption using RC6."""
        rc6 = RC6Encryption(self.rc6_key)
        padded_data = pad(data, self.block_size)
        blocks = [padded_data[i:i+self.block_size] 
                 for i in range(0, len(padded_data), self.block_size)]
        
        ciphertext = b''
        prev_block = iv
        
        for block in blocks:
            # XOR with previous ciphertext block (or IV for first block)
            xored = self._xor_bytes(block, prev_block)
            # Convert to hex for RC6Encryption
            xored_hex = xored.hex()
            # Encrypt block
            encrypted_hex = rc6.encrypt(xored_hex)
            # Convert back to bytes
            encrypted_block = bytes.fromhex(encrypted_hex)
            ciphertext += encrypted_block
            prev_block = encrypted_block
        
        return ciphertext
    
    def _cbc_decrypt(self, data: bytes, iv: bytes) -> bytes:
        """Implement CBC mode decryption using RC6."""
        rc6 = RC6Encryption(self.rc6_key)
        blocks = [data[i:i+self.block_size] 
                 for i in range(0, len(data), self.block_size)]
        
        plaintext = b''
        prev_block = iv
        
        for block in blocks:
            # Convert to hex for RC6Encryption
            block_hex = block.hex()
            # Decrypt block
            decrypted_hex = rc6.decrypt(block_hex)
            # Convert back to bytes
            decrypted_block = bytes.fromhex(decrypted_hex)
            # XOR with previous ciphertext block (or IV for first block)
            xored = self._xor_bytes(decrypted_block, prev_block)
            plaintext += xored
            prev_block = block
        
        return plaintext
    
    def encrypt_chunk(self, chunk: bytes, iv: bytes, chunk_index: int) -> bytes:
        """Encrypt chunk using RC6-CBC."""
        chunk_iv = self._get_chunk_iv(iv, chunk_index)
        return self._cbc_encrypt(chunk, chunk_iv)
    
    def decrypt_chunk(self, chunk: bytes, iv: bytes, chunk_index: int, is_last: bool = False) -> bytes:
        """Decrypt chunk using RC6-CBC."""
        chunk_iv = self._get_chunk_iv(iv, chunk_index)
        plaintext = self._cbc_decrypt(chunk, chunk_iv)
        if is_last:
            return unpad(plaintext, self.block_size)
        return plaintext


class CipherFactory:
    """Factory class for creating cipher instances."""
    
    @staticmethod
    def create_cipher(algorithm: str, key: bytes) -> CipherBase:
        """Create cipher instance based on algorithm."""
        if algorithm == 'aes':
            return AESCipher(key)
        elif algorithm == 'rc6':
            return RC6Cipher(key)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")


class FileEncryptor:
    """Main class for file encryption/decryption operations."""
    
    def __init__(self, file_handler: FileHandler, key_manager: KeyManager):
        self.file_handler = file_handler
        self.key_manager = key_manager
    
    def encrypt_file(self, input_path: Path, algorithm: str, 
                    key: Optional[bytes] = None, 
                    password: Optional[str] = None) -> Tuple[Path, str]:
        """Encrypt a file with segmentation support."""
        # Prepare encryption parameters
        salt = get_random_bytes(SALT_SIZE) if password else b'\x00' * SALT_SIZE
        iv = get_random_bytes(AES_BLOCK_SIZE)
        
        # Handle key
        if password:
            actual_key = self.key_manager.derive_key_from_password(password, salt)
            key_info = "Password-derived key"
        else:
            actual_key = key if key else self.key_manager.generate_random_key()
            key_info = self.key_manager.encode_key(actual_key) if not key else "User-provided key"
        
        # Create cipher
        cipher = CipherFactory.create_cipher(algorithm, actual_key)
        
        # Prepare output file
        output_path = self._create_output_path(input_path, 'encrypt', algorithm)
        
        # Get file info
        file_size = self.file_handler.get_file_size(input_path)
        chunk_count = self.file_handler.calculate_chunk_count(file_size)
        
        # Create metadata
        metadata = EncryptionMetadata(
            algorithm=algorithm,
            salt=salt,
            iv=iv,
            original_size=file_size,
            chunk_count=chunk_count
        )
        
        # Encrypt file
        with open(output_path, 'wb') as out_file:
            # Write metadata
            out_file.write(metadata.to_bytes())
            
            # Encrypt and write chunks
            total_chunks = chunk_count
            for chunk_index, chunk in self.file_handler.read_chunks(input_path):
                # Show progress for large files
                if total_chunks > 10 and chunk_index % 10 == 0:
                    progress = (chunk_index / total_chunks) * 100
                    print(f"  Encrypting... {progress:.1f}%", end='\r')
                
                encrypted_chunk = cipher.encrypt_chunk(chunk, iv, chunk_index)
                out_file.write(encrypted_chunk)
            
            if total_chunks > 10:
                print("  Encrypting... 100.0%")
        
        return output_path, key_info
    
    def decrypt_file(self, input_path: Path, algorithm: str,
                    key: Optional[bytes] = None,
                    password: Optional[str] = None) -> Path:
        """Decrypt a file with segmentation support."""
        with open(input_path, 'rb') as in_file:
            # Read metadata
            metadata_bytes = in_file.read(45)  # Size of serialized metadata
            metadata = EncryptionMetadata.from_bytes(metadata_bytes)
            
            # Verify algorithm matches
            if metadata.algorithm != algorithm:
                raise ValueError(f"Algorithm mismatch: file uses {metadata.algorithm}, but {algorithm} specified")
            
            # Handle key
            if password:
                if metadata.salt == b'\x00' * SALT_SIZE:
                    raise ValueError("File was not encrypted with a password")
                actual_key = self.key_manager.derive_key_from_password(password, metadata.salt)
            else:
                if not key:
                    raise ValueError("Decryption requires either key or password")
                actual_key = key
            
            # Create cipher
            cipher = CipherFactory.create_cipher(algorithm, actual_key)
            
            # Prepare output file
            output_path = self._create_output_path(input_path, 'decrypt', algorithm)
            
            # Decrypt file
            with open(output_path, 'wb') as out_file:
                chunk_index = 0
                bytes_written = 0
                
                while chunk_index < metadata.chunk_count:
                    # Show progress for large files
                    if metadata.chunk_count > 10 and chunk_index % 10 == 0:
                        progress = (chunk_index / metadata.chunk_count) * 100
                        print(f"  Decrypting... {progress:.1f}%", end='\r')
                    
                    # Calculate chunk size based on whether it's the last chunk
                    is_last_chunk = chunk_index == metadata.chunk_count - 1
                    
                    if is_last_chunk:
                        remaining_bytes = metadata.original_size - bytes_written
                        # Calculate padded size for last chunk
                        padded_size = ((remaining_bytes + cipher.block_size - 1) 
                                     // cipher.block_size) * cipher.block_size
                        chunk = in_file.read(padded_size)
                    else:
                        # Regular chunk size (padded)
                        padded_chunk_size = ((self.file_handler.chunk_size + cipher.block_size - 1) 
                                           // cipher.block_size) * cipher.block_size
                        chunk = in_file.read(padded_chunk_size)
                    
                    if not chunk:
                        break
                    
                    # Decrypt chunk
                    decrypted_chunk = cipher.decrypt_chunk(chunk, metadata.iv, chunk_index, is_last_chunk)
                    
                    # Handle last chunk to ensure correct file size
                    if is_last_chunk:
                        bytes_to_write = metadata.original_size - bytes_written
                        decrypted_chunk = decrypted_chunk[:bytes_to_write]
                    
                    out_file.write(decrypted_chunk)
                    bytes_written += len(decrypted_chunk)
                    chunk_index += 1
                
                if metadata.chunk_count > 10:
                    print("  Decrypting... 100.0%")
        
        return output_path
    
    def _create_output_path(self, input_path: Path, operation: str, algorithm: str) -> Path:
        """Generate output filename based on operation."""
        suffix = '.enc' if operation == 'encrypt' else '.dec'
        stem = input_path.stem
        
        # Remove .enc suffix when decrypting
        if operation == 'decrypt' and stem.endswith('.enc'):
            stem = stem[:-4]
        
        return input_path.parent / f"{stem}_{algorithm}{suffix}{input_path.suffix}"


class CLIHandler:
    """Handles command-line interface."""
    
    @staticmethod
    def create_parser() -> argparse.ArgumentParser:
        """Create command line argument parser."""
        parser = argparse.ArgumentParser(
            description="Client-side file encryption tool with large file support",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Encrypt with auto-generated key
  %(prog)s encrypt -a aes largefile.zip
  
  # Encrypt with password
  %(prog)s encrypt -a rc6 -p "my secret password" video.mp4
  
  # Encrypt with specific key
  %(prog)s encrypt -a aes -k "base64_encoded_key" document.pdf
  
  # Decrypt with key
  %(prog)s decrypt -a aes -k "base64_encoded_key" document_aes.enc.pdf
  
  # Decrypt with password
  %(prog)s decrypt -a rc6 -p "my secret password" video_rc6.enc.mp4
"""
        )
        
        parser.add_argument('operation', choices=['encrypt', 'decrypt'], 
                          help='Operation to perform')
        parser.add_argument('file', type=Path, help='File to process')
        parser.add_argument('-a', '--algorithm', choices=['aes', 'rc6'], 
                          default='aes', help='Encryption algorithm (default: aes)')
        
        key_group = parser.add_mutually_exclusive_group()
        key_group.add_argument('-k', '--key', help='Base64-encoded encryption key')
        key_group.add_argument('-p', '--password', help='Password for key derivation')
        
        parser.add_argument('-c', '--chunk-size', type=int, 
                          default=CHUNK_SIZE // (1024 * 1024),
                          help='Chunk size in MB (default: 1)')
        
        return parser
    
    @staticmethod
    def validate_args(args) -> None:
        """Validate command line arguments."""
        if not args.file.exists():
            raise FileNotFoundError(f"File '{args.file}' not found")
        
        if args.algorithm == 'rc6' and not RC6_AVAILABLE:
            raise RuntimeError("RC6Encryption not available. Please install: pip install RC6Encryption")
        
        if args.operation == 'decrypt' and not args.key and not args.password:
            raise ValueError("Decryption requires either --key or --password")
        
        if args.chunk_size < 1:
            raise ValueError("Chunk size must be at least 1 MB")


class Application:
    """Main application class."""
    
    def __init__(self):
        self.cli_handler = CLIHandler()
        self.key_manager = KeyManager()
        self.file_handler = None
        self.file_encryptor = None
    
    def run(self):
        """Run the application."""
        parser = self.cli_handler.create_parser()
        args = parser.parse_args()
        
        try:
            # Validate arguments
            self.cli_handler.validate_args(args)
            
            # Initialize components with custom chunk size
            chunk_size = args.chunk_size * 1024 * 1024
            self.file_handler = FileHandler(chunk_size)
            self.file_encryptor = FileEncryptor(self.file_handler, self.key_manager)
            
            # Process key if provided
            key = None
            if args.key:
                try:
                    key = self.key_manager.decode_key(args.key)
                except Exception:
                    raise ValueError("Invalid base64 key format")
            
            # Perform operation
            if args.operation == 'encrypt':
                output_path, key_info = self.file_encryptor.encrypt_file(
                    args.file, args.algorithm, key, args.password
                )
                print(f"✓ File encrypted successfully: {output_path}")
                if not args.key and not args.password:
                    print(f"🔑 Generated key (save this!): {key_info}")
            else:
                output_path = self.file_encryptor.decrypt_file(
                    args.file, args.algorithm, key, args.password
                )
                print(f"✓ File decrypted successfully: {output_path}")
        
        except KeyboardInterrupt:
            print("\n⚠️  Operation cancelled by user")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error: {str(e)}", file=sys.stderr)
            sys.exit(1)


def main():
    """Entry point."""
    app = Application()
    app.run()


if __name__ == "__main__":
    main()