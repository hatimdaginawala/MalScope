"""
File analyzer for PE file identification and metadata
"""

import os
import pefile
import magic
from datetime import datetime
from typing import Optional, Dict
from ..common.models import PEInfo


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
        
        # Detect file type using magic
        try:
            mime_type = magic.from_file(file_path, mime=True)
            file_type = magic.from_file(file_path)
        except:
            mime_type = 'application/octet-stream'
            file_type = 'Unknown'
        
        # Parse PE file
        pe = None
        pe_type = 'unknown'
        arch = 'unknown'
        compile_time = None
        linker_version = None
        entry_point = None
        image_base = None
        subsystem = None
        
        try:
            pe = pefile.PE(file_path)
            
            # Determine PE type
            if pe.is_dll():
                pe_type = 'dll'
            elif pe.is_exe():
                pe_type = 'exe'
            elif pe.is_driver():
                pe_type = 'sys'
            else:
                pe_type = 'unknown'
            
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
            if hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
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
            # Not a valid PE file
            pe_type = 'invalid'
        except Exception as e:
            # Other errors
            pass
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