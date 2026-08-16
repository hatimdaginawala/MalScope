"""
File analyzer for PE file identification and metadata
"""

import os
import pefile
from datetime import datetime
from typing import Optional, Dict
from common.models import PEInfo


class FileAnalyzer:
    """Analyze PE file metadata and identify file type"""
    
    @staticmethod
    def analyze(file_path: str) -> PEInfo:
        """
        Analyze PE file and extract metadata
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            PEInfo object with file metadata
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = os.path.getsize(file_path)
        
        # Detect file type using pefile
        mime_type = 'application/octet-stream'
        file_type = 'Unknown'
        pe_type = 'unknown'
        arch = 'unknown'
        compile_time = None
        linker_version = None
        entry_point = None
        image_base = None
        subsystem = None
        
        # Try to parse as PE
        pe = None
        try:
            pe = pefile.PE(file_path)
            
            # Determine PE type
            if pe.is_dll():
                pe_type = 'dll'
                file_type = 'Windows DLL'
                mime_type = 'application/x-msdownload'
            elif pe.is_exe():
                pe_type = 'exe'
                file_type = 'Windows Executable'
                mime_type = 'application/x-msdownload'
            elif pe.is_driver():
                pe_type = 'sys'
                file_type = 'Windows Driver'
                mime_type = 'application/x-msdownload'
            else:
                pe_type = 'unknown'
                file_type = 'Windows Portable Executable'
                mime_type = 'application/x-msdownload'
            
            # Determine architecture
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                arch = 'x64'
            elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                arch = 'x86'
            elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']:
                arch = 'x86'
            else:
                arch = 'unknown'
            
            # Extract compile time
            if hasattr(pe.FILE_HEADER, 'TimeDateStamp') and pe.FILE_HEADER.TimeDateStamp:
                compile_time = datetime.fromtimestamp(
                    pe.FILE_HEADER.TimeDateStamp
                ).isoformat()
            
            # Extract linker version
            if hasattr(pe.OPTIONAL_HEADER, 'MajorLinkerVersion'):
                linker_version = f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"
            
            # Extract entry point
            if hasattr(pe.OPTIONAL_HEADER, 'AddressOfEntryPoint'):
                entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            
            # Extract image base
            if hasattr(pe.OPTIONAL_HEADER, 'ImageBase'):
                image_base = pe.OPTIONAL_HEADER.ImageBase
            
            # Extract subsystem
            if hasattr(pe.OPTIONAL_HEADER, 'Subsystem'):
                subsystem_map = {
                    1: 'Native',
                    2: 'Windows GUI',
                    3: 'Windows CUI',
                    5: 'OS/2 CUI',
                    7: 'POSIX CUI',
                    9: 'Windows CE GUI',
                    10: 'EFI Application',
                    11: 'EFI Boot Service Driver',
                    12: 'EFI Runtime Driver',
                    13: 'EFI ROM',
                    14: 'Xbox',
                }
                subsystem = subsystem_map.get(pe.OPTIONAL_HEADER.Subsystem, 'Unknown')
            
        except pefile.PEFormatError:
            # Not a valid PE file - check if it might be something else
            file_type = 'Not a PE file'
            pe_type = 'invalid'
        except Exception as e:
            # Other errors
            file_type = f'Error parsing: {str(e)}'
            pe_type = 'error'
        finally:
            if pe:
                pe.close()
        
        return PEInfo(
            filename=os.path.basename(file_path),
            file_size=file_size,
            file_type=file_type,
            mime_type=mime_type,
            pe_type=pe_type,
            arch=arch,
            compile_time=compile_time,
            linker_version=linker_version,
            entry_point=entry_point,
            image_base=image_base,
            subsystem=subsystem,
        )