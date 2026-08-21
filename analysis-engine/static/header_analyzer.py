"""
PE header analyzer
"""

import pefile
from datetime import datetime
from typing import List, Optional

# Use absolute imports
from common.models import DOSHeader, COFFHeader, OptionalHeader, DataDirectory


class HeaderAnalyzer:
    """Analyze PE headers"""
    
    @staticmethod
    def analyze_dos_header(pe: pefile.PE) -> DOSHeader:
        """Analyze DOS header"""
        dos = pe.DOS_HEADER
        
        return DOSHeader(
            magic=hex(dos.e_magic),
            e_cblp=dos.e_cblp,
            e_cp=dos.e_cp,
            e_crlc=dos.e_crlc,
            e_cparhdr=dos.e_cparhdr,
            e_minalloc=dos.e_minalloc,
            e_maxalloc=dos.e_maxalloc,
            e_ss=dos.e_ss,
            e_sp=dos.e_sp,
            e_csum=dos.e_csum,
            e_ip=dos.e_ip,
            e_cs=dos.e_cs,
            e_lfarlc=dos.e_lfarlc,
            e_ovno=dos.e_ovno,
            e_res=list(dos.e_res[:4]) if dos.e_res else [0, 0, 0, 0],
            e_oemid=dos.e_oemid,
            e_oeminfo=dos.e_oeminfo,
            e_res2=list(dos.e_res2[:10]) if dos.e_res2 else [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            e_lfanew=dos.e_lfanew,
        )
    
    @staticmethod
    def analyze_coff_header(pe: pefile.PE) -> COFFHeader:
        """Analyze COFF file header"""
        coff = pe.FILE_HEADER
        
        machine_map = {
            0x0: 'Unknown',
            0x14c: 'I386',
            0x8664: 'AMD64',
            0x1a2: 'IA64',
            0x284: 'ARM',
            0xaa64: 'ARM64',
        }
        
        return COFFHeader(
            machine=machine_map.get(coff.Machine, 'Unknown'),
            number_of_sections=coff.NumberOfSections,
            time_date_stamp=datetime.fromtimestamp(coff.TimeDateStamp).isoformat(),
            pointer_to_symbol_table=coff.PointerToSymbolTable,
            number_of_symbols=coff.NumberOfSymbols,
            size_of_optional_header=coff.SizeOfOptionalHeader,
            characteristics=hex(coff.Characteristics),
        )
    
    @staticmethod
    def _safe_get_opt_attr(opt, attr_name, default=0):
        """Safely get attribute from optional header"""
        return getattr(opt, attr_name, default)
    
    @staticmethod
    def analyze_optional_header(pe: pefile.PE) -> OptionalHeader:
        """Analyze optional header"""
        opt = pe.OPTIONAL_HEADER
        
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
        
        magic_map = {
            0x10b: 'PE32',
            0x20b: 'PE32+',
        }
        
        # Use safe attribute access for all optional header fields
        return OptionalHeader(
            magic=magic_map.get(HeaderAnalyzer._safe_get_opt_attr(opt, 'Magic'), 'Unknown'),
            major_linker_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MajorLinkerVersion'),
            minor_linker_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MinorLinkerVersion'),
            size_of_code=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfCode'),
            size_of_initialized_data=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfInitializedData'),
            size_of_uninitialized_data=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfUninitializedData'),
            address_of_entry_point=HeaderAnalyzer._safe_get_opt_attr(opt, 'AddressOfEntryPoint'),
            base_of_code=HeaderAnalyzer._safe_get_opt_attr(opt, 'BaseOfCode'),
            base_of_data=HeaderAnalyzer._safe_get_opt_attr(opt, 'BaseOfData', 0),
            image_base=HeaderAnalyzer._safe_get_opt_attr(opt, 'ImageBase'),
            section_alignment=HeaderAnalyzer._safe_get_opt_attr(opt, 'SectionAlignment'),
            file_alignment=HeaderAnalyzer._safe_get_opt_attr(opt, 'FileAlignment'),
            major_operating_system_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MajorOperatingSystemVersion'),
            minor_operating_system_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MinorOperatingSystemVersion'),
            major_image_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MajorImageVersion'),
            minor_image_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MinorImageVersion'),
            major_subsystem_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MajorSubsystemVersion'),
            minor_subsystem_version=HeaderAnalyzer._safe_get_opt_attr(opt, 'MinorSubsystemVersion'),
            win32_version_value=HeaderAnalyzer._safe_get_opt_attr(opt, 'Win32VersionValue'),
            size_of_image=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfImage'),
            size_of_headers=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfHeaders'),
            checksum=HeaderAnalyzer._safe_get_opt_attr(opt, 'CheckSum'),
            subsystem=subsystem_map.get(HeaderAnalyzer._safe_get_opt_attr(opt, 'Subsystem'), 'Unknown'),
            dll_characteristics=HeaderAnalyzer._safe_get_opt_attr(opt, 'DllCharacteristics'),
            size_of_stack_reserve=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfStackReserve'),
            size_of_stack_commit=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfStackCommit'),
            size_of_heap_reserve=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfHeapReserve'),
            size_of_heap_commit=HeaderAnalyzer._safe_get_opt_attr(opt, 'SizeOfHeapCommit'),
            loader_flags=HeaderAnalyzer._safe_get_opt_attr(opt, 'LoaderFlags'),
            number_of_rva_and_sizes=HeaderAnalyzer._safe_get_opt_attr(opt, 'NumberOfRvaAndSizes'),
        )
    
    @staticmethod
    def analyze_data_directories(pe: pefile.PE) -> List[DataDirectory]:
        """Analyze data directories"""
        directories = []
        
        if not hasattr(pe, 'OPTIONAL_HEADER') or not hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY'):
            return directories
        
        dir_names = {
            0: 'Export',
            1: 'Import',
            2: 'Resource',
            3: 'Exception',
            4: 'Security',
            5: 'Base Relocation',
            6: 'Debug',
            7: 'Architecture',
            8: 'Global Ptr',
            9: 'TLS',
            10: 'Load Config',
            11: 'Bound Import',
            12: 'IAT',
            13: 'Delay Import',
            14: 'COM Descriptor',
        }
        
        for idx, directory in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
            if directory.VirtualAddress != 0 or directory.Size != 0:
                directories.append(DataDirectory(
                    name=dir_names.get(idx, f'Directory_{idx}'),
                    virtual_address=directory.VirtualAddress,
                    size=directory.Size,
                ))
        
        return directories