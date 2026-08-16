"""
Section analyzer for PE file sections
"""

import pefile
import math
from typing import List
from common.models import SectionInfo


class SectionAnalyzer:
    """Analyze PE file sections"""
    
    @staticmethod
    def analyze(pe: pefile.PE) -> List[SectionInfo]:
        """
        Analyze PE sections and extract information
        
        Args:
            pe: PE file object
            
        Returns:
            List of SectionInfo objects
        """
        sections = []
        
        if not hasattr(pe, 'sections'):
            return sections
        
        for section in pe.sections:
            # Get section characteristics as readable string
            characteristics = hex(section.Characteristics)
            
            # Calculate entropy for the section
            entropy = SectionAnalyzer._calculate_entropy(section.get_data())
            
            sections.append(SectionInfo(
                name=section.Name.decode('utf-8').rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                characteristics=characteristics,
                entropy=entropy,
            ))
        
        return sections
    
    @staticmethod
    def _calculate_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of data
        
        Args:
            data: Bytes to analyze
            
        Returns:
            Entropy value (0.0 to 8.0)
        """
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        
        # Count byte frequencies
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # Calculate entropy
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy