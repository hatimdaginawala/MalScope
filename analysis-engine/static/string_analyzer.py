"""
String analyzer for extracting strings from PE files
"""

import pefile
import re
from typing import List
from common.models import StringInfo


class StringAnalyzer:
    """Extract and analyze strings from PE files"""
    
    # Patterns for suspicious strings
    SUSPICIOUS_PATTERNS = [
        r'cmd\.exe',
        r'powershell\.exe',
        r'wscript\.exe',
        r'cscript\.exe',
        r'rundll32\.exe',
        r'regsvr32\.exe',
        r'http://',
        r'https://',
        r'\.onion',
        r'\.tor',
        r'C:\\Windows\\System32\\',
        r'C:\\Users\\',
        r'\\AppData\\',
        r'\\Temp\\',
        r'system32',
        r'SYSTEM\\CurrentControlSet',
        r'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
        r'Schedule',
        r'Service',
        r'CreateProcess',
        r'WriteProcessMemory',
        r'VirtualAlloc',
        r'LoadLibrary',
        r'GetProcAddress',
    ]
    
    # Minimum string length
    MIN_STRING_LENGTH = 4
    
    @staticmethod
    def analyze(pe: pefile.PE) -> StringInfo:
        """
        Extract strings from PE file
        
        Args:
            pe: PE file object
            
        Returns:
            StringInfo object
        """
        # Extract data from all sections
        data = b''
        if hasattr(pe, 'sections'):
            for section in pe.sections:
                data += section.get_data()
        
        # Extract ASCII strings
        ascii_strings = StringAnalyzer._extract_ascii_strings(data)
        
        # Extract Unicode strings
        unicode_strings = StringAnalyzer._extract_unicode_strings(data)
        
        # Find suspicious strings
        suspicious = StringAnalyzer._find_suspicious_strings(ascii_strings + unicode_strings)
        
        return StringInfo(
            ascii=ascii_strings[:1000],  # Limit to avoid huge lists
            unicode=unicode_strings[:500],
            suspicious=suspicious[:100],
        )
    
    @staticmethod
    def _extract_ascii_strings(data: bytes) -> List[str]:
        """Extract ASCII strings from binary data"""
        strings = []
        current = []
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current.append(chr(byte))
            else:
                if len(current) >= StringAnalyzer.MIN_STRING_LENGTH:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= StringAnalyzer.MIN_STRING_LENGTH:
            strings.append(''.join(current))
        
        return strings
    
    @staticmethod
    def _extract_unicode_strings(data: bytes) -> List[str]:
        """Extract Unicode strings from binary data"""
        strings = []
        current = []
        
        for i in range(0, len(data) - 1, 2):
            if i + 1 >= len(data):
                break
            
            byte1 = data[i]
            byte2 = data[i + 1]
            
            if byte2 == 0 and 32 <= byte1 <= 126:  # Unicode printable
                current.append(chr(byte1))
            else:
                if len(current) >= StringAnalyzer.MIN_STRING_LENGTH:
                    strings.append(''.join(current))
                current = []
        
        if len(current) >= StringAnalyzer.MIN_STRING_LENGTH:
            strings.append(''.join(current))
        
        return strings
    
    @staticmethod
    def _find_suspicious_strings(strings: List[str]) -> List[str]:
        """Find suspicious strings using patterns"""
        suspicious = []
        
        for s in strings:
            s_lower = s.lower()
            for pattern in StringAnalyzer.SUSPICIOUS_PATTERNS:
                if re.search(pattern, s_lower, re.IGNORECASE):
                    suspicious.append(s)
                    break
        
        return suspicious