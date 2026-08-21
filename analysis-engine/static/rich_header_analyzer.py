"""
Rich header analyzer
"""

import pefile
import struct
from typing import List, Optional

# Use absolute imports
from common.models import RichHeader, RichHeaderEntry


class RichHeaderAnalyzer:
    """Analyze Rich header (Microsoft Visual Studio metadata)"""
    
    @staticmethod
    def analyze(pe: pefile.PE) -> Optional[RichHeader]:
        """Analyze Rich header"""
        if not hasattr(pe, 'rich_header'):
            return None
        
        rich = pe.rich_header
        
        entries = []
        if hasattr(rich, 'values'):
            for value in rich.values:
                entries.append(RichHeaderEntry(
                    product_id=value.product_id,
                    build_id=value.build_id,
                    count=value.count,
                ))
        
        return RichHeader(
            checksum=rich.checksum if hasattr(rich, 'checksum') else 0,
            entries=entries,
        )