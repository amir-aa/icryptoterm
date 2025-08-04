#!/usr/bin/env python3
"""
Comprehensive test suite for the CTR mode file encryption tool.
Tests cover success paths, edge cases, and failure scenarios.
"""

import pytest
import os
import sys
import tempfile
import shutil
from pathlib import Path
import base64
import secrets
from unittest.mock import Mock, patch, MagicMock
import struct

# Add the parent directory to the path to import the encryption tool
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptoterm import (
    KeyManager, FileHandler, AESCipher, RC6CipherCTR, CipherFactory,
    FileEncryptor, EncryptionMetadata, Application, CLIHandler,
    DEFAULT_KEY_SIZE, CHUNK_SIZE, NONCE_SIZE
)


class TestKeyManager:
    """Test cases for KeyManager class."""
    
    def test_generate_random_key_default_size(self):
        """Test generating a random key with default size."""
        key = KeyManager.generate_random_key()
        assert len(key) == DEFAULT_KEY_SIZE
        assert isinstance(key, bytes)
    
    def test_generate_random_key_custom_size(self):
        """Test generating a random key with custom size."""
        key = KeyManager.generate_random_key(16)
        assert len(key) == 16
    
    def test_generate_random_keys_are_unique(self):
        """Test that generated keys are unique."""
        keys = [KeyManager.generate_random_key() for _ in range(10)]
        assert len(set(keys)) == 10
    
    def test_derive_key_from_password(self):
        """Test password-based key derivation."""
        password = "test_password_123"
        salt = b'salt' * 4  # 16 bytes
        key = KeyManager.derive_key_from_password(password, salt)
        assert len(key) == DEFAULT_KEY_SIZE
        assert isinstance(key, bytes)
    
    def test_derive_key_deterministic(self):
        """Test that same password and salt produce same key."""
        password = "consistent_password"
        salt = b'fixed_salt_16byt'
        key1 = KeyManager.derive_key_from_password(password, salt)
        key2 = KeyManager.derive_key_from_password(password, salt)
        assert key1 == key2
    
    def test_derive_key_different_salts(self):
        """Test that different salts produce different keys."""
        password = "same_password"
        salt1 = b'salt1_16_bytes!!'
        salt2 = b'salt2_16_bytes!!'
        key1 = KeyManager.derive_key_from_password(password, salt1)
        key2 = KeyManager.derive_key_from_password(password, salt2)
        assert key1 != key2
    
    def test_encode_decode_key(self):
        """Test key encoding and decoding."""
        original_key = secrets.token_bytes(32)
        encoded = KeyManager.encode_key(original_key)
        decoded = KeyManager.decode_key(encoded)
        assert decoded == original_key
        assert isinstance(encoded, str)
    
    def test_decode_invalid_base64(self):
        """Test decoding invalid base64 string."""
        with pytest.raises(Exception):
            KeyManager.decode_key("not valid base64!@#$")


class TestFileHandler:
    """Test cases for FileHandler class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def test_file(self, temp_dir):
        """Create a test file with known content."""
        file_path = temp_dir / "test_file.txt"
        content = b"Hello, World!" * 1000  # ~13KB
        file_path.write_bytes(content)
        return file_path, content
    
    def test_read_chunks_small_file(self, test_file):
        """Test reading chunks from a small file."""
        file_path, content = test_file
        handler = FileHandler(chunk_size=1024)  # 1KB chunks
        
        chunks = list(handler.read_chunks(file_path))
        assert len(chunks) == 13  # ~13KB file with 1KB chunks
        
        # Verify chunk indices
        for i, (index, chunk) in enumerate(chunks):
            assert index == i
        
        # Reconstruct and verify content
        reconstructed = b''.join(chunk for _, chunk in chunks)
        assert reconstructed == content
    
    def test_read_chunks_exact_size(self, temp_dir):
        """Test reading file that's exactly chunk size."""
        file_path = temp_dir / "exact_size.bin"
        content = b'X' * 1024  # Exactly 1KB
        file_path.write_bytes(content)
        
        handler = FileHandler(chunk_size=1024)
        chunks = list(handler.read_chunks(file_path))
        
        assert len(chunks) == 1
        assert chunks[0][0] == 0
        assert chunks[0][1] == content
    
    def test_read_chunks_empty_file(self, temp_dir):
        """Test reading chunks from empty file."""
        file_path = temp_dir / "empty.txt"
        file_path.touch()
        
        handler = FileHandler()
        chunks = list(handler.read_chunks(file_path))
        assert len(chunks) == 0
    
    def test_read_chunks_large_file_simulation(self, temp_dir):
        """Test reading chunks from a larger file."""
        file_path = temp_dir / "large.bin"
        # Create 5KB file
        content = secrets.token_bytes(5120)
        file_path.write_bytes(content)
        
        handler = FileHandler(chunk_size=1024)  # 1KB chunks
        chunks = list(handler.read_chunks(file_path))
        
        assert len(chunks) == 5  # 5KB / 1KB = 5 chunks
        
        # Verify total size
        total_read = sum(len(chunk) for _, chunk in chunks)
        assert total_read == len(content)
    
    def test_get_file_size(self, test_file):
        """Test getting file size."""
        file_path, content = test_file
        handler = FileHandler()
        size = handler.get_file_size(file_path)
        assert size == len(content)
    
    def test_calculate_chunk_count(self):
        """Test chunk count calculation."""
        handler = FileHandler(chunk_size=1024)
        
        # Test various file sizes
        assert handler.calculate_chunk_count(0) == 0
        assert handler.calculate_chunk_count(1) == 1
        assert handler.calculate_chunk_count(1024) == 1
        assert handler.calculate_chunk_count(1025) == 2
        assert handler.calculate_chunk_count(10240) == 10


class TestEncryptionMetadata:
    """Test cases for EncryptionMetadata class."""
    
    def test_metadata_serialization_aes(self):
        """Test metadata serialization and deserialization for AES."""
        metadata = EncryptionMetadata(
            algorithm='aes',
            salt=b'salt' * 4,  # 16 bytes
            nonce=b'nonce123',  # 8 bytes
            original_size=12345,
            chunk_count=10
        )
        
        serialized = metadata.to_bytes()
        assert len(serialized) == 37  # 1 + 16 + 8 + 8 + 4 = 37 bytes
        
        deserialized = EncryptionMetadata.from_bytes(serialized)
        assert deserialized.algorithm == metadata.algorithm
        assert deserialized.salt == metadata.salt
        assert deserialized.nonce == metadata.nonce
        assert deserialized.original_size == metadata.original_size
        assert deserialized.chunk_count == metadata.chunk_count
    
    def test_metadata_serialization_rc6(self):
        """Test metadata serialization for RC6."""
        metadata = EncryptionMetadata(
            algorithm='rc6',
            salt=b'x' * 16,
            nonce=b'y' * 8,
            original_size=54321,
            chunk_count=20
        )
        
        serialized = metadata.to_bytes()
        deserialized = EncryptionMetadata.from_bytes(serialized)
        
        assert deserialized.algorithm == 'rc6'
        assert deserialized.original_size == 54321
        assert deserialized.chunk_count == 20
    
    def test_metadata_algorithm_encoding(self):
        """Test algorithm encoding in metadata."""
        # Test AES
        metadata_aes = EncryptionMetadata('aes', b'x'*16, b'y'*8, 100, 1)
        serialized_aes = metadata_aes.to_bytes()
        assert serialized_aes[0:1] == b'A'
        
        # Test RC6
        metadata_rc6 = EncryptionMetadata('rc6', b'x'*16, b'y'*8, 100, 1)
        serialized_rc6 = metadata_rc6.to_bytes()
        assert serialized_rc6[0:1] == b'R'
    
    def test_metadata_large_values(self):
        """Test metadata with large file sizes."""
        large_size = 2**40  # 1TB
        metadata = EncryptionMetadata(
            algorithm='aes',
            salt=b'x' * 16,
            nonce=b'y' * 8,
            original_size=large_size,
            chunk_count=1000000
        )
        
        serialized = metadata.to_bytes()
        deserialized = EncryptionMetadata.from_bytes(serialized)
        assert deserialized.original_size == large_size
        assert deserialized.chunk_count == 1000000
    
    def test_metadata_zero_values(self):
        """Test metadata with zero values."""
        metadata = EncryptionMetadata(
            algorithm='aes',
            salt=b'\x00' * 16,
            nonce=b'\x00' * 8,
            original_size=0,
            chunk_count=0
        )
        
        serialized = metadata.to_bytes()
        deserialized = EncryptionMetadata.from_bytes(serialized)
        assert deserialized.original_size == 0
        assert deserialized.chunk_count == 0


class TestCiphers:
    """Test cases for cipher implementations."""
    
    @pytest.fixture
    def test_key(self):
        """Generate a test key."""
        return secrets.token_bytes(32)
    
    @pytest.fixture
    def test_nonce(self):
        """Generate a test nonce."""
        return secrets.token_bytes(8)
    
    def test_aes_cipher_encrypt_decrypt(self, test_key, test_nonce):
        """Test AES encryption and decryption in CTR mode."""
        cipher = AESCipher(test_key)
        plaintext = b"Test data for AES encryption in CTR mode"
        
        # Encrypt
        ciphertext = cipher.encrypt_chunk(plaintext, test_nonce, 0)
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)  # CTR mode preserves length
        
        # Decrypt
        decrypted = cipher.decrypt_chunk(ciphertext, test_nonce, 0)
        assert decrypted == plaintext
    
    def test_aes_cipher_different_chunks_same_data(self, test_key, test_nonce):
        """Test that different chunks produce different ciphertexts."""
        cipher = AESCipher(test_key)
        plaintext = b"Same data for different chunks"
        
        ciphertext1 = cipher.encrypt_chunk(plaintext, test_nonce, 0)
        ciphertext2 = cipher.encrypt_chunk(plaintext, test_nonce, 1)
        
        assert ciphertext1 != ciphertext2  # Different due to different counters
    
    def test_aes_cipher_different_nonces(self, test_key):
        """Test that different nonces produce different ciphertexts."""
        cipher = AESCipher(test_key)
        plaintext = b"Same data, different nonces"
        
        nonce1 = b'nonce001'
        nonce2 = b'nonce002'
        
        ciphertext1 = cipher.encrypt_chunk(plaintext, nonce1, 0)
        ciphertext2 = cipher.encrypt_chunk(plaintext, nonce2, 0)
        
        assert ciphertext1 != ciphertext2
    
    def test_rc6_cipher_encrypt_decrypt(self, test_key, test_nonce):
        """Test RC6 encryption and decryption in CTR mode."""
        cipher = RC6CipherCTR(test_key)
        plaintext = b"Test data for RC6 encryption in CTR mode"
        
        # Encrypt
        ciphertext = cipher.encrypt_chunk(plaintext, test_nonce, 0)
        assert ciphertext != plaintext
        assert len(ciphertext) == len(plaintext)  # CTR mode preserves length
        
        # Decrypt
        decrypted = cipher.decrypt_chunk(ciphertext, test_nonce, 0)
        assert decrypted == plaintext
    
    def test_rc6_cipher_keystream_uniqueness(self, test_key, test_nonce):
        """Test RC6 keystream uniqueness for different chunks."""
        cipher = RC6CipherCTR(test_key)
        plaintext = b"X" * 64  # 64 bytes of same data
        
        ciphertext1 = cipher.encrypt_chunk(plaintext, test_nonce, 0)
        ciphertext2 = cipher.encrypt_chunk(plaintext, test_nonce, 1)
        
        assert ciphertext1 != ciphertext2
    
    def test_cipher_factory_aes(self, test_key):
        """Test cipher factory for AES."""
        cipher = CipherFactory.create_cipher('aes', test_key)
        assert isinstance(cipher, AESCipher)
    
    def test_cipher_factory_rc6(self, test_key):
        """Test cipher factory for RC6."""
        cipher = CipherFactory.create_cipher('rc6', test_key)
        assert isinstance(cipher, RC6CipherCTR)
    
    def test_cipher_factory_invalid_algorithm(self, test_key):
        """Test cipher factory with invalid algorithm."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            CipherFactory.create_cipher('invalid', test_key)
    
    def test_cipher_empty_data(self, test_key, test_nonce):
        """Test encrypting empty data."""
        cipher = AESCipher(test_key)
        plaintext = b""
        
        ciphertext = cipher.encrypt_chunk(plaintext, test_nonce, 0)
        assert len(ciphertext) == 0  # CTR mode preserves empty length
        
        decrypted = cipher.decrypt_chunk(ciphertext, test_nonce, 0)
        assert decrypted == plaintext
    
    def test_cipher_large_chunk(self, test_key, test_nonce):
        """Test encrypting large chunk."""
        cipher = AESCipher(test_key)
        # Create 1MB of random data
        plaintext = secrets.token_bytes(1024 * 1024)
        
        ciphertext = cipher.encrypt_chunk(plaintext, test_nonce, 0)
        assert len(ciphertext) == len(plaintext)
        
        decrypted = cipher.decrypt_chunk(ciphertext, test_nonce, 0)
        assert decrypted == plaintext
    
    def test_counter_calculation(self, test_key):
        """Test counter start calculation for different chunks."""
        cipher = AESCipher(test_key)
        
        # Test counter start calculation
        chunk_size = 1024
        counter_start_0 = cipher._calculate_counter_start(0, chunk_size)
        counter_start_1 = cipher._calculate_counter_start(1, chunk_size)
        counter_start_2 = cipher._calculate_counter_start(2, chunk_size)
        
        assert counter_start_0 == 0
        assert counter_start_1 > counter_start_0
        assert counter_start_2 > counter_start_1


class TestFileEncryptor:
    """Test cases for FileEncryptor class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def encryptor(self):
        """Create FileEncryptor instance."""
        file_handler = FileHandler()
        key_manager = KeyManager()
        return FileEncryptor(file_handler, key_manager)
    
    def test_encrypt_decrypt_small_file_aes(self, encryptor, temp_dir):
        """Test encrypting and decrypting a small file with AES."""
        # Create test file
        test_file = temp_dir / "small.txt"
        original_content = b"Small file content for AES CTR testing"
        test_file.write_bytes(original_content)
        
        # Encrypt with auto-generated key
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        assert encrypted_file.exists()
        assert encrypted_file != test_file
        assert key_str != "User-provided key"
        
        # Verify encrypted content is different
        encrypted_content = encrypted_file.read_bytes()
        assert len(encrypted_content) > len(original_content)  # Due to metadata
        
        # Decrypt
        key = KeyManager.decode_key(key_str)
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        assert decrypted_file.exists()
        
        # Verify content matches exactly
        assert decrypted_file.read_bytes() == original_content
    
    def test_encrypt_decrypt_small_file_rc6(self, encryptor, temp_dir):
        """Test encrypting and decrypting a small file with RC6."""
        # Create test file
        test_file = temp_dir / "small_rc6.txt"
        original_content = b"Small file content for RC6 CTR testing"
        test_file.write_bytes(original_content)
        
        # Encrypt with auto-generated key
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'rc6')
        key = KeyManager.decode_key(key_str)
        
        # Decrypt
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'rc6', key=key)
        
        # Verify content matches exactly
        assert decrypted_file.read_bytes() == original_content
    
    def test_encrypt_decrypt_with_password(self, encryptor, temp_dir):
        """Test encryption and decryption with password."""
        # Create test file
        test_file = temp_dir / "password_test.txt"
        original_content = b"Secret content for password testing"
        test_file.write_bytes(original_content)
        
        password = "super_secret_password_123"
        
        # Encrypt with password
        encrypted_file, key_info = encryptor.encrypt_file(
            test_file, 'aes', password=password
        )
        assert key_info == "Password-derived key"
        
        # Decrypt with same password
        decrypted_file = encryptor.decrypt_file(
            encrypted_file, 'aes', password=password
        )
        
        # Verify content matches
        assert decrypted_file.read_bytes() == original_content
    
    def test_encrypt_large_file_multiple_chunks(self, encryptor, temp_dir):
        """Test encrypting a file with multiple chunks."""
        # Create test file with 3MB of data
        test_file = temp_dir / "large.bin"
        chunk_size = 1024 * 1024  # 1MB
        num_chunks = 3
        original_content = secrets.token_bytes(chunk_size * num_chunks)
        test_file.write_bytes(original_content)
        
        # Use smaller chunk size for testing
        file_handler = FileHandler(chunk_size=chunk_size)
        key_manager = KeyManager()
        test_encryptor = FileEncryptor(file_handler, key_manager)
        
        # Encrypt
        encrypted_file, key_str = test_encryptor.encrypt_file(test_file, 'aes')
        key = KeyManager.decode_key(key_str)
        
        # Verify metadata
        with open(encrypted_file, 'rb') as f:
            metadata_bytes = f.read(37)  # CTR mode metadata size
            metadata = EncryptionMetadata.from_bytes(metadata_bytes)
            assert metadata.chunk_count == num_chunks
            assert metadata.original_size == len(original_content)
        
        # Decrypt
        decrypted_file = test_encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        
        # Verify content matches exactly
        decrypted_content = decrypted_file.read_bytes()
        assert decrypted_content == original_content
        assert len(decrypted_content) == len(original_content)
    
    def test_decrypt_wrong_password(self, encryptor, temp_dir):
        """Test decrypting with wrong password should fail."""
        # Create and encrypt file
        test_file = temp_dir / "wrong_pass.txt"
        test_file.write_bytes(b"Secret data")
        
        encrypted_file, _ = encryptor.encrypt_file(
            test_file, 'aes', password="correct_password"
        )
        
        # Try to decrypt with wrong password - should produce garbage
        decrypted_file = encryptor.decrypt_file(
            encrypted_file, 'aes', password="wrong_password"
        )
        
        # Content should be different (garbage)
        decrypted_content = decrypted_file.read_bytes()
        assert decrypted_content != b"Secret data"
    
    def test_decrypt_wrong_algorithm(self, encryptor, temp_dir):
        """Test decrypting with wrong algorithm."""
        # Create and encrypt file with AES
        test_file = temp_dir / "algo_test.txt"
        test_file.write_bytes(b"Test data")
        
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        key = KeyManager.decode_key(key_str)
        
        # Try to decrypt with RC6
        with pytest.raises(ValueError, match="Algorithm mismatch"):
            encryptor.decrypt_file(encrypted_file, 'rc6', key=key)
    
    def test_encrypt_empty_file(self, encryptor, temp_dir):
        """Test encrypting an empty file."""
        # Create empty file
        test_file = temp_dir / "empty.txt"
        test_file.touch()
        
        # Encrypt
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        key = KeyManager.decode_key(key_str)
        
        # Verify encrypted file contains only metadata
        encrypted_content = encrypted_file.read_bytes()
        assert len(encrypted_content) == 37  # Only metadata
        
        # Decrypt
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        
        # Verify empty
        assert decrypted_file.read_bytes() == b""
    
    def test_encrypt_odd_size_file(self, encryptor, temp_dir):
        """Test encrypting file with odd size (not multiple of block size)."""
        # Create file with 1023 bytes (not multiple of 16)
        test_file = temp_dir / "odd_size.bin"
        original_content = secrets.token_bytes(1023)
        test_file.write_bytes(original_content)
        
        # Encrypt and decrypt
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        key = KeyManager.decode_key(key_str)
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        
        # Verify exact size preservation
        decrypted_content = decrypted_file.read_bytes()
        assert len(decrypted_content) == 1023
        assert decrypted_content == original_content
    
    def test_output_filename_generation(self, encryptor, temp_dir):
        """Test output filename generation."""
        test_file = temp_dir / "document.pdf"
        test_file.touch()
        
        # Test encryption naming
        enc_path = encryptor._create_output_path(test_file, 'encrypt', 'aes')
        assert enc_path.name == "document_aes.enc.pdf"
        
        # Test decryption naming
        dec_path = encryptor._create_output_path(enc_path, 'decrypt', 'aes')
        assert dec_path.name == "document_aes.dec.pdf"
    
    def test_file_size_preservation_various_sizes(self, encryptor, temp_dir):
        """Test that various file sizes are preserved exactly."""
        test_sizes = [0, 1, 15, 16, 17, 31, 32, 33, 1023, 1024, 1025, 4096]
        
        for size in test_sizes:
            test_file = temp_dir / f"test_{size}.bin"
            original_content = secrets.token_bytes(size) if size > 0 else b""
            test_file.write_bytes(original_content)
            
            # Encrypt and decrypt
            encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
            key = KeyManager.decode_key(key_str)
            decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
            
            # Verify exact size and content
            decrypted_content = decrypted_file.read_bytes()
            assert len(decrypted_content) == size, f"Size mismatch for {size} bytes"
            assert decrypted_content == original_content, f"Content mismatch for {size} bytes"
            
            # Cleanup
            test_file.unlink()
            encrypted_file.unlink()
            decrypted_file.unlink()


class TestCLIHandler:
    """Test cases for CLI handler."""
    
    def test_parser_creation(self):
        """Test argument parser creation."""
        parser = CLIHandler.create_parser()
        assert parser is not None
        
        # Test help text contains CTR mode reference
        help_text = parser.format_help()
        assert "CTR mode" in help_text
    
    def test_validate_args_missing_file(self):
        """Test validation with missing file."""
        args = Mock()
        args.file = Path("nonexistent.txt")
        args.operation = 'encrypt'
        args.algorithm = 'aes'
        args.key = None
        args.password = None
        args.chunk_size = 1
        
        with pytest.raises(FileNotFoundError):
            CLIHandler.validate_args(args)
    
    def test_validate_args_decrypt_no_key(self, tmp_path):
        """Test validation for decrypt without key or password."""
        test_file = tmp_path / "test.txt"
        test_file.touch()
        
        args = Mock()
        args.file = test_file
        args.operation = 'decrypt'
        args.algorithm = 'aes'
        args.key = None
        args.password = None
        args.chunk_size = 1
        
        with pytest.raises(ValueError, match="requires either --key or --password"):
            CLIHandler.validate_args(args)
    
    def test_validate_args_invalid_chunk_size(self, tmp_path):
        """Test validation with invalid chunk size."""
        test_file = tmp_path / "test.txt"
        test_file.touch()
        
        args = Mock()
        args.file = test_file
        args.operation = 'encrypt'
        args.algorithm = 'aes'
        args.key = None
        args.password = None
        args.chunk_size = 0
        
        with pytest.raises(ValueError, match="at least 1 MB"):
            CLIHandler.validate_args(args)


class TestApplication:
    """Test cases for main Application class."""
    
    @pytest.fixture
    def mock_args(self, tmp_path):
        """Create mock arguments."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("Test content")
        
        args = Mock()
        args.file = test_file
        args.operation = 'encrypt'
        args.algorithm = 'aes'
        args.key = None
        args.password = None
        args.chunk_size = 1
        return args
    
    def test_application_run_encrypt_success(self, mock_args, capsys):
        """Test successful encryption run."""
        with patch('sys.argv', ['prog', 'encrypt', '-a', 'aes', str(mock_args.file)]):
            app = Application()
            
            # Mock the file encryptor to avoid actual encryption
            with patch.object(app, 'file_encryptor') as mock_encryptor:
                mock_encryptor.encrypt_file.return_value = (
                    Path("encrypted.enc"), "test_key_base64"
                )
                
                # Mock argument parser
                with patch('argparse.ArgumentParser.parse_args', return_value=mock_args):
                    app.run()
            
            captured = capsys.readouterr()
            assert "✓ File encrypted successfully" in captured.out
            assert "🔑 Generated key" in captured.out
    
   
    def test_application_run_invalid_key(self, mock_args, capsys):
        """Test application with invalid base64 key."""
        mock_args.key = "invalid_base64!!!"
        
        with patch('argparse.ArgumentParser.parse_args', return_value=mock_args):
            app = Application()
            with pytest.raises(SystemExit) as exc_info:
                app.run()
        
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "Invalid base64 key format" in captured.err


class TestIntegration:
    """Integration tests for the complete encryption tool."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for tests."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)
    
    def test_end_to_end_aes_key(self, temp_dir):
        """Test complete encryption/decryption cycle with AES and key."""
        # Setup
        file_handler = FileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        # Create test file with various content
        test_file = temp_dir / "integration_test.bin"
        test_content = b"Start" + secrets.token_bytes(10000) + b"End"
        test_file.write_bytes(test_content)
        
        # Encrypt
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        key = key_manager.decode_key(key_str)
        
        # Verify encrypted file is different and right size
        encrypted_content = encrypted_file.read_bytes()
        assert encrypted_content != test_content
        # CTR mode: encrypted size = original size + metadata
        assert len(encrypted_content) == len(test_content) + 37
        
        # Decrypt
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        
        # Verify content matches exactly
        decrypted_content = decrypted_file.read_bytes()
        assert decrypted_content == test_content
        assert len(decrypted_content) == len(test_content)
    
    def test_end_to_end_rc6_password(self, temp_dir):
        """Test complete cycle with RC6 and password-based encryption."""
        # Setup
        file_handler = FileHandler(chunk_size=512)  # Small chunks for testing
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        # Create test file
        test_file = temp_dir / "password_test.txt"
        test_content = ("Secret message " * 100).encode()
        test_file.write_bytes(test_content)
        
        password = "very_secure_password_123!"
        
        # Encrypt with password
        encrypted_file, _ = encryptor.encrypt_file(
            test_file, 'rc6', password=password
        )
        
        # Decrypt with same password
        decrypted_file = encryptor.decrypt_file(
            encrypted_file, 'rc6', password=password
        )
        
        # Verify
        decrypted_content = decrypted_file.read_bytes()
        assert decrypted_content == test_content
        assert len(decrypted_content) == len(test_content)
        
        # Test wrong password produces different result
        wrong_decrypted = encryptor.decrypt_file(
            encrypted_file, 'rc6', password="wrong_password"
        )
        wrong_content = wrong_decrypted.read_bytes()
        assert wrong_content != test_content
    
    def test_large_file_handling_simulation(self, temp_dir):
        """Test handling of large files through chunking."""
        # Create a mock file handler that simulates large file
        class MockLargeFileHandler(FileHandler):
            def __init__(self):
                super().__init__(chunk_size=1024)  # 1KB chunks
            
            def read_chunks(self, file_path):
                # Simulate 1000 chunks (1MB total)
                for i in range(1000):
                    yield i, b'X' * 1024
            
            def get_file_size(self, file_path):
                return 1024 * 1000  # 1MB
        
        # Test encryption with mock
        file_handler = MockLargeFileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        test_file = temp_dir / "mock_large.bin"
        test_file.touch()
        
        # Should handle without loading entire file into memory
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        
        # Verify metadata shows correct chunk count
        with open(encrypted_file, 'rb') as f:
            metadata_bytes = f.read(37)
            metadata = EncryptionMetadata.from_bytes(metadata_bytes)
            assert metadata.chunk_count == 1000
            assert metadata.original_size == 1024 * 1000


class TestEdgeCases:
    """Test edge cases and boundary conditions."""
    
    def test_max_file_size_metadata(self):
        """Test metadata with maximum file size."""
        max_size = 2**64 - 1  # Maximum 64-bit unsigned integer
        metadata = EncryptionMetadata(
            algorithm='aes',
            salt=b'x' * 16,
            nonce=b'y' * 8,
            original_size=max_size,
            chunk_count=1
        )
        
        # Should handle without overflow
        serialized = metadata.to_bytes()
        deserialized = EncryptionMetadata.from_bytes(serialized)
        assert deserialized.original_size == max_size
    
    def test_unicode_filename_handling(self, tmp_path):
        """Test handling of Unicode filenames."""
        # Create file with Unicode name
        test_file = tmp_path / "测试文件_🔐_CTR.txt"
        test_content = b"Unicode filename test with CTR mode"
        test_file.write_bytes(test_content)
        
        file_handler = FileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        # Should handle Unicode filenames
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        assert encrypted_file.exists()
        
        # Decrypt
        key = key_manager.decode_key(key_str)
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        assert decrypted_file.read_bytes() == test_content
    
    def test_special_characters_in_password(self):
        """Test passwords with special characters."""
        special_passwords = [
            "パスワード123",  # Japanese
            "密码@#$%^&*()",  # Chinese with symbols
            "🔐🔑🗝️💻",  # Emojis
            "\n\t\r\x00",  # Control characters
            "' OR '1'='1 --",  # SQL injection attempt
            "password with spaces and symbols !@#$%^&*()",
        ]
        
        for password in special_passwords:
            salt = b'test_salt_16byte'
            key = KeyManager.derive_key_from_password(password, salt)
            assert len(key) == DEFAULT_KEY_SIZE
    
    def test_nonce_uniqueness_across_encryptions(self, tmp_path):
        """Test that different encryptions use different nonces."""
        test_file = tmp_path / "nonce_test.txt"
        test_file.write_bytes(b"Same content")
        
        file_handler = FileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        # Encrypt same file multiple times
        nonces = []
        for i in range(10):
            encrypted_file, _ = encryptor.encrypt_file(test_file, 'aes')
            
            # Extract nonce from metadata
            with open(encrypted_file, 'rb') as f:
                metadata_bytes = f.read(37)
                metadata = EncryptionMetadata.from_bytes(metadata_bytes)
                nonces.append(metadata.nonce)
            
            encrypted_file.unlink()  # Cleanup
        
        # All nonces should be unique
        assert len(set(nonces)) == 10
    
    def test_chunk_counter_overflow_protection(self):
        """Test that chunk counter calculations don't overflow."""
        cipher = AESCipher(secrets.token_bytes(32))
        
        # Test with very large chunk indices
        large_chunk_index = 2**30  # 1 billion
        chunk_size = 1024 * 1024  # 1MB
        
        # Should not raise overflow error
        counter_start = cipher._calculate_counter_start(large_chunk_index, chunk_size)
        assert isinstance(counter_start, int)
        assert counter_start >= 0


class TestFailureScenarios:
    """Test various failure scenarios."""
    
    def test_corrupted_metadata(self, tmp_path):
        """Test handling of corrupted metadata."""
        # Create a fake encrypted file with corrupted metadata
        fake_encrypted = tmp_path / "corrupted.enc"
        fake_encrypted.write_bytes(b"This is not valid metadata" + b"x" * 100)
        
        file_handler = FileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        key = key_manager.generate_random_key()
        
        # Should fail when trying to read metadata
        with pytest.raises(Exception):
            encryptor.decrypt_file(fake_encrypted, 'aes', key=key)
    
    def test_truncated_encrypted_file(self, tmp_path):
        """Test handling of truncated encrypted file."""
        # Create and encrypt a file
        test_file = tmp_path / "original.txt"
        test_file.write_bytes(b"Original content")
        
        file_handler = FileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        encrypted_file, key_str = encryptor.encrypt_file(test_file, 'aes')
        key = key_manager.decode_key(key_str)
        
        # Truncate the encrypted file
        with open(encrypted_file, 'r+b') as f:
            f.truncate(40)  # Keep only metadata + few bytes
        
        # Should handle gracefully (may produce partial output)
        decrypted_file = encryptor.decrypt_file(encrypted_file, 'aes', key=key)
        decrypted_content = decrypted_file.read_bytes()
        
        # Should not crash, but content will be different
        assert len(decrypted_content) <= len(b"Original content")
    
    def test_permission_denied_simulation(self, tmp_path, monkeypatch):
        """Simulate permission denied errors."""
        test_file = tmp_path / "test.txt"
        test_file.write_bytes(b"Test content")
        
        file_handler = FileHandler()
        key_manager = KeyManager()
        encryptor = FileEncryptor(file_handler, key_manager)
        
        # Mock open to raise PermissionError
        original_open = open
        def mock_open(file, mode='r', **kwargs):
            if 'wb' in mode and 'enc' in str(file):
                raise PermissionError("Permission denied")
            return original_open(file, mode, **kwargs)
        
        monkeypatch.setattr("builtins.open", mock_open)
        
        with pytest.raises(PermissionError):
            encryptor.encrypt_file(test_file, 'aes')
    
    def test_invalid_key_sizes(self):
        """Test cipher initialization with invalid key sizes."""
        # Test RC6 with invalid key size
        with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
            from cryptoterm import RC6Cipher
            RC6Cipher(b"short_key")
        
        with pytest.raises(ValueError, match="Key must be 16, 24, or 32 bytes"):
            from cryptoterm import RC6Cipher
            RC6Cipher(b"way_too_long_key_that_exceeds_32_bytes_limit")


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main([
        __file__,
        "-v",
        "--tb=short",
        "--cov=cryptoterm",
        "--cov-report=term-missing",
        "--cov-report=html"
    ])