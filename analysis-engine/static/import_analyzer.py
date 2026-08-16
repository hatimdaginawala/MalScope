"""
Import analyzer for PE file imports
"""

import pefile
from typing import List
from ..common.models import ImportInfo


class ImportAnalyzer:
    """Analyze PE file imports"""
    
    # Suspicious import functions to flag
    SUSPICIOUS_APIS = [
        'CreateRemoteThread',
        'WriteProcessMemory',
        'VirtualAllocEx',
        'CreateProcess',
        'WinExec',
        'ShellExecute',
        'RegSetValueEx',
        'CreateService',
        'StartService',
        'InternetOpen',
        'URLDownloadToFile',
        'GetAsyncKeyState',
        'SetWindowsHookEx',
        'ReadProcessMemory',
        'NtCreateThreadEx',
        'NtQueueApcThread',
        'SetThreadContext',
        'CreateToolhelp32Snapshot',
        'Process32First',
        'Process32Next',
        'OpenProcess',
        'TerminateProcess',
        'CreateRemoteThread',
        'VirtualProtectEx',
        'WriteProcessMemory',
    ]
    
    @staticmethod
    def analyze(pe: pefile.PE) -> List[ImportInfo]:
        """
        Analyze PE imports
        
        Args:
            pe: PE file object
            
        Returns:
            List of ImportInfo objects
        """
        imports = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports
        
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8') if entry.dll else 'Unknown'
            functions = []
            
            for imp in entry.imports:
                if imp.name:
                    functions.append(imp.name.decode('utf-8'))
                elif imp.ordinal:
                    functions.append(f"Ordinal_{imp.ordinal}")
            
            if functions:
                imports.append(ImportInfo(
                    dll=dll_name,
                    functions=functions,
                ))
        
        return imports
    
    @staticmethod
    def get_suspicious_imports(imports: List[ImportInfo]) -> List[str]:
        """
        Get list of suspicious imports found
        
        Args:
            imports: List of ImportInfo objects
            
        Returns:
            List of suspicious function names
        """
        suspicious = []
        
        for imp in imports:
            for func in imp.functions:
                if func in ImportAnalyzer.SUSPICIOUS_APIS:
                    suspicious.append(func)
        
        return suspicious