"""
Digital signature analyzer
"""

import pefile
from datetime import datetime
from typing import Optional

# Use absolute imports
from common.models import SignatureInfo


class SignatureAnalyzer:
    """Analyze digital signatures"""
    
    @staticmethod
    def analyze(pe: pefile.PE) -> SignatureInfo:
        """Analyze digital signature"""
        signed = False
        signer = None
        issuer = None
        serial_number = None
        valid_from = None
        valid_to = None
        algorithm = None
        timestamp = None
        verification_result = None
        certificate_chain = []
        
        # Check if signed
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            signed = True
            
            # Try to extract signature information
            try:
                sec = pe.DIRECTORY_ENTRY_SECURITY
                if sec and sec.struct and sec.struct.Size > 0:
                    verification_result = 'Present (detailed parsing requires additional libraries)'
            except:
                pass
        
        return SignatureInfo(
            signed=signed,
            signer=signer,
            issuer=issuer,
            serial_number=serial_number,
            valid_from=valid_from,
            valid_to=valid_to,
            algorithm=algorithm,
            timestamp=timestamp,
            verification_result=verification_result,
            certificate_chain=certificate_chain,
        )