"""
Entropy analyzer for PE file sections
"""

import pefile
import math
from typing import List, Dict
from ..common.models import EntropyInfo


class EntropyAnalyzer:
    """Analyze entropy of PE file sections"""
    
    @staticmethod
    def analyze(pe: pefile.PE) -> EntropyInfo:
        """
        Analyze entropy of PE sections
        
        Args:
            pe: PE file object
            
        Returns:
            EntropyInfo object
        """
        sections = []
        high_entropy = []
        total_entropy = 0.0
        
        if not hasattr(pe, 'sections'):
            return EntropyInfo()
        
        for section in pe.sections:
            data = section.get_data()
            entropy = EntropyAnalyzer._calculate_entropy(data)
            
            section_info = {
                'name': section.Name.decode('utf-8').rstrip('\x00'),
                'entropy': entropy,
            }
            sections.append(section_info)
            
            total_entropy += entropy
            
            # Flag high entropy sections (potential encryption/packing)
            if entropy > 7.0:
                high_entropy.append(section_info['name'])
        
        # Calculate overall entropy
        overall = total_entropy / len(sections) if sections else 0.0
        
        return EntropyInfo(
            overall=overall,
            sections=sections,
            high_entropy_sections=high_entropy,
        )
    
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