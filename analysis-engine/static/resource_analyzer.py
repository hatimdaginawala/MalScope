"""
Resource Analyzer - Deep analysis of PE resources
"""

import pefile
import hashlib
import json
import math
import os
from typing import List, Dict, Any, Optional
from common.models import ResourceDetails


class ResourceAnalyzer:
    """Analyze PE resources in depth"""
    
    def __init__(self):
        self.resource_types = self._load_resource_types()
        self.suspicious_patterns = self._load_suspicious_patterns()
    
    def _load_resource_types(self) -> Dict[str, Dict]:
        """Load resource type definitions from JSON"""
        try:
            json_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'common', 'resource_types.json'
            )
            with open(json_path, 'r') as f:
                data = json.load(f)
            return data.get('resource_types', {})
        except Exception:
            return {}
    
    def _load_suspicious_patterns(self) -> List[str]:
        """Load patterns for suspicious resources"""
        return [
            b'<script',
            b'<html',
            b'function(',
            b'var ',
            b'class ',
            b'def ',
            b'import ',
            b'export ',
            b'powershell',
            b'cmd.exe',
            b'System.Diagnostics',
            b'System.IO',
            b'System.Net',
            b'WebClient',
            b'DownloadFile',
            b'CreateProcess',
            b'ShellExecute',
            b'RegSetValue',
            b'WriteProcessMemory',
            b'VirtualAlloc',
            b'CreateRemoteThread',
            b'rundll32',
            b'regsvr32',
            b'.onion',
            b'bitcoin',
            b'monero',
            b'wallet',
            b'ransom',
            b'encrypt',
            b'decrypt',
        ]
    
    def analyze(self, pe: pefile.PE) -> List[ResourceDetails]:
        """Analyze all resources in the PE file"""
        resources = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_id = resource_type.struct.Id
            type_name = pefile.RESOURCE_TYPE.get(type_id, f"Type_{type_id}")
            
            # Get type metadata
            type_metadata = self.resource_types.get(type_name, {})
            type_category = type_metadata.get('category', 'unknown')
            type_severity = type_metadata.get('severity', 'medium')
            
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    try:
                        # Get resource data
                        data = pe.get_data(
                            resource_lang.data.struct.OffsetToData,
                            resource_lang.data.struct.Size
                        )
                        
                        if data:
                            # Calculate entropy
                            entropy = self._calculate_entropy(data)
                            
                            # Check if suspicious
                            is_suspicious, reason, indicators = self._check_suspicious(data)
                            
                            resources.append(ResourceDetails(
                                type=type_name,
                                type_id=type_id,
                                type_category=type_category,
                                type_severity=type_severity,
                                id=resource_id.struct.Id,
                                language=resource_lang.struct.Id,
                                size=len(data),
                                sha256=hashlib.sha256(data).hexdigest(),
                                entropy=entropy,
                                is_suspicious=is_suspicious,
                                suspicious_reason=reason,
                                embedded_indicators=indicators,
                            ))
                    except Exception:
                        continue
        
        return resources
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        entropy = 0.0
        length = len(data)
        freq = {}
        
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _check_suspicious(self, data: bytes) -> tuple:
        """Check if resource contains suspicious content"""
        indicators = []
        
        for pattern in self.suspicious_patterns:
            if pattern in data:
                indicators.append(pattern.decode('utf-8', errors='ignore'))
        
        if indicators:
            reason = f"Contains {len(indicators)} suspicious patterns: {', '.join(indicators[:3])}"
            return True, reason, indicators[:10]
        
        return False, None, []
    
    def get_summary(self, resources: List[ResourceDetails]) -> Dict:
        """Get summary of resource analysis"""
        total = len(resources)
        suspicious = len([r for r in resources if r.is_suspicious])
        
        # Group by category
        categories = {}
        for r in resources:
            categories[r.type_category] = categories.get(r.type_category, 0) + 1
        
        # Group by type
        types = {}
        for r in resources:
            types[r.type] = types.get(r.type, 0) + 1
        
        # Calculate total size
        total_size = sum(r.size for r in resources)
        
        return {
            'total_resources': total,
            'suspicious_resources': suspicious,
            'total_size': total_size,
            'categories': categories,
            'types': types,
            'has_suspicious': suspicious > 0,
        }