"""
Pytest configuration file for the CTR mode encryption tool tests.
"""

import pytest
import sys
import os
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope="session")
def temp_test_dir():
    """Create a temporary directory for the entire test session."""
    temp_dir = tempfile.mkdtemp(prefix="encryption_tests_")
    yield Path(temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def cleanup_test_files():
    """Automatically cleanup test files after each test."""
    yield
    # Additional cleanup if needed
    pass


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "ctr_mode: marks tests specific to CTR mode functionality"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Mark integration tests
        if "integration" in item.nodeid.lower():
            item.add_marker(pytest.mark.integration)
        
        # Mark CTR mode specific tests
        if any(keyword in item.name.lower() for keyword in ["ctr", "counter", "nonce"]):
            item.add_marker(pytest.mark.ctr_mode)
        
        # Mark slow tests
        if any(keyword in item.name.lower() for keyword in ["large", "simulation", "end_to_end"]):
            item.add_marker(pytest.mark.slow)


@pytest.fixture
def sample_data():
    """Provide sample data for tests."""
    return {
        'small': b"Small test data",
        'medium': b"Medium test data " * 100,
        'large': b"Large test data " * 10000,
        'binary': bytes(range(256)),
        'unicode': "Unicode test data: 测试数据 🔐".encode('utf-8')
    }