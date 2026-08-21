"""
TLS (Thread Local Storage) analyzer
"""

import pefile
from typing import Optional

# Use absolute imports
from common.models import TLSEntry


class TLSAnalyzer:
    """Analyze TLS data"""
    
    @staticmethod
    def analyze(pe: pefile.PE) -> Optional[TLSEntry]:
        """Analyze TLS directory"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            return None
        
        tls = pe.DIRECTORY_ENTRY_TLS
        
        return TLSEntry(
            start_address_of_raw_data=tls.struct.StartAddressOfRawData,
            end_address_of_raw_data=tls.struct.EndAddressOfRawData,
            address_of_index=tls.struct.AddressOfIndex,
            address_of_callbacks=tls.struct.AddressOfCallBacks,
            size_of_zero_fill=tls.struct.SizeOfZeroFill,
            characteristics=tls.struct.Characteristics,
        )