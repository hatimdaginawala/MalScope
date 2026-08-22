"""
Certificate Analyzer - Analyze digital signatures and certificates
"""

import pefile
import re
from typing import Optional, List
from common.models import CertificateInfo, SignatureAnalysisResult


class CertificateAnalyzer:
    """Analyze digital signatures and certificates"""
    
    def analyze(self, pe: pefile.PE) -> SignatureAnalysisResult:
        """Analyze digital signature in PE file"""
        
        # Check if the PE has a security directory
        is_signed = False
        has_security_dir = False
        
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            has_security_dir = True
            if pe.DIRECTORY_ENTRY_SECURITY.struct.Size > 0:
                is_signed = True
        
        # If not signed, return basic result
        if not is_signed:
            return SignatureAnalysisResult(
                is_signed=False,
                verification_status="Not signed",
                certificate_chain=[],
                certificate_count=0,
            )
        
        # Try to extract certificate information
        cert_info = self._extract_certificate_info(pe)
        
        # Try to extract timestamp info
        timestamp_info = self._extract_timestamp_info(pe)
        
        # Build certificate chain
        chain = []
        if cert_info:
            chain.append(cert_info)
        
        return SignatureAnalysisResult(
            is_signed=True,
            signer=cert_info.subject if cert_info else None,
            issuer=cert_info.issuer if cert_info else None,
            serial_number=cert_info.serial_number if cert_info else None,
            valid_from=cert_info.valid_from if cert_info else None,
            valid_to=cert_info.valid_to if cert_info else None,
            algorithm=cert_info.algorithm if cert_info else None,
            timestamp=timestamp_info.get('timestamp') if timestamp_info else None,
            timestamp_authority=timestamp_info.get('authority') if timestamp_info else None,
            verification_status="Present (detailed parsing requires additional libraries)",
            certificate_chain=chain,
            certificate_count=1,
            is_timestamped=bool(timestamp_info),
            is_trusted=False,  # Would require full chain validation
            is_expired=self._check_expired(cert_info) if cert_info else False,
            warnings=[
                "Certificate validation limited to presence check",
                "Full certificate chain validation requires additional libraries"
            ] if is_signed else [],
        )
    
    def _extract_certificate_info(self, pe: pefile.PE) -> Optional[CertificateInfo]:
        """Extract certificate information from PE"""
        # This is a simplified extraction
        # Full ASN.1 parsing would require libraries like asn1crypto
        
        # Check if we can find certificate data in the security directory
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            try:
                # Try to extract basic info from the security directory
                sec = pe.DIRECTORY_ENTRY_SECURITY
                if sec.struct.Size > 0:
                    # For now, return a placeholder with basic info
                    # Full extraction would parse the ASN.1 data
                    return CertificateInfo(
                        subject="Certificate found (details require ASN.1 parsing)",
                        issuer="Certificate found (details require ASN.1 parsing)",
                        serial_number="Unknown",
                        valid_from="Unknown",
                        valid_to="Unknown",
                        algorithm="Unknown",
                        signature_algorithm="Unknown",
                        thumbprint="Unknown",
                        subject_alt_names=[],
                        key_usage=[],
                        extended_key_usage=[],
                        is_ca=False,
                        is_self_signed=False,
                        revocation_status="Unknown",
                    )
            except Exception:
                pass
        
        return None
    
    def _extract_timestamp_info(self, pe: pefile.PE) -> Optional[Dict]:
        """Extract timestamp information"""
        # This would require parsing the ASN.1 data
        # Placeholder for now
        return None
    
    def _check_expired(self, cert_info: Optional[CertificateInfo]) -> bool:
        """Check if certificate is expired"""
        if not cert_info or not cert_info.valid_to:
            return False
        
        # Would need to parse the date and compare to now
        # Placeholder
        return False