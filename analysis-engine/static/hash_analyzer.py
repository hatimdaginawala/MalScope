"""
Hash analyzer for calculating file hashes
"""

import hashlib
import os
from typing import Dict


class HashAnalyzer:
    """Calculate cryptographic hashes of files"""
    
    @staticmethod
    def calculate_hashes(file_path: str) -> Dict[str, str]:
        """
        Calculate SHA256, MD5, and SHA1 hashes of a file
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with hash values
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        sha256_hash = hashlib.sha256()
        md5_hash = hashlib.md5()
        sha1_hash = hashlib.sha1()
        
        with open(file_path, 'rb') as f:
            # Read file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
                md5_hash.update(byte_block)
                sha1_hash.update(byte_block)
        
        return {
            'sha256': sha256_hash.hexdigest(),
            'md5': md5_hash.hexdigest(),
            'sha1': sha1_hash.hexdigest(),
        }