"""
Debug information analyzer
"""

import pefile
from datetime import datetime
from typing import Optional

# Use absolute imports
from common.models import DebugInfo


class DebugAnalyzer:
    """Analyze debug information"""
    
    @staticmethod
    def analyze(pe: pefile.PE) -> Optional[DebugInfo]:
        """Analyze debug directory"""
        if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            return None
        
        for debug in pe.DIRECTORY_ENTRY_DEBUG:
            if hasattr(debug, 'entry') and hasattr(debug.entry, 'Type'):
                debug_type = debug.entry.Type
                
                type_map = {
                    1: 'COFF',
                    2: 'CodeView',
                    3: 'FPO',
                    4: 'Misc',
                    5: 'Exception',
                    6: 'Fixup',
                    7: 'OMAP to source',
                    8: 'OMAP from source',
                    9: 'Borland',
                    10: 'Reserved10',
                    11: 'CLSID',
                }
                
                # Try to extract CodeView info
                if debug_type == 2 and hasattr(debug, 'entry') and hasattr(debug.entry, 'Structure'):
                    try:
                        cv = debug.entry.Structure
                        if hasattr(cv, 'Guid') and hasattr(cv, 'Age'):
                            guid = cv.Guid
                            if hasattr(cv, 'PdbFileName'):
                                pdb = cv.PdbFileName.decode('utf-8').rstrip('\x00')
                            else:
                                pdb = None
                            
                            return DebugInfo(
                                type=type_map.get(debug_type, 'Unknown'),
                                age=cv.Age,
                                guid=str(guid),
                                pdb_filename=pdb,
                            )
                    except:
                        pass
                
                return DebugInfo(
                    type=type_map.get(debug_type, 'Unknown'),
                )
        
        return None