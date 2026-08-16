"""
YARA analyzer for scanning files with YARA rules
"""

import os
import yara
import glob
from typing import List, Dict, Any
from ..common.models import YARAMatch


class YARAAnalyzer:
    """Scan files using YARA rules"""
    
    def __init__(self, rules_dir: str = None):
        """
        Initialize YARA analyzer
        
        Args:
            rules_dir: Directory containing YARA rule files
        """
        self.rules_dir = rules_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            '..', 'rules', 'yara'
        )
        self.compiled_rules = None
        self._load_rules()
    
    def _load_rules(self):
        """Load YARA rules from directory"""
        if not os.path.exists(self.rules_dir):
            return
        
        # Find all .yar and .yara files
        rule_files = []
        for ext in ['*.yar', '*.yara']:
            rule_files.extend(glob.glob(os.path.join(self.rules_dir, ext)))
        
        if not rule_files:
            return
        
        try:
            # Compile rules
            self.compiled_rules = yara.compile(filepaths={
                os.path.basename(f): f for f in rule_files
            })
        except yara.SyntaxError as e:
            print(f"YARA syntax error: {e}")
        except Exception as e:
            print(f"YARA compilation error: {e}")
    
    def scan(self, file_path: str) -> List[YARAMatch]:
        """
        Scan a file with YARA rules
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            List of YARAMatch objects
        """
        if not self.compiled_rules:
            return []
        
        if not os.path.exists(file_path):
            return []
        
        try:
            matches = self.compiled_rules.match(file_path)
            
            result = []
            for match in matches:
                # Extract matched strings
                matched_strings = []
                for string_name, string_data in match.strings.items():
                    matched_strings.append({
                        'id': string_name,
                        'string': string_data[0],
                        'offset': string_data[1],
                        'length': len(string_data[0]),
                    })
                
                result.append(YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace or 'default',
                    tags=match.tags or [],
                    meta=match.meta or {},
                    strings=matched_strings,
                ))
            
            return result
            
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []
    
    def scan_data(self, data: bytes, filename: str = None) -> List[YARAMatch]:
        """
        Scan data with YARA rules
        
        Args:
            data: Bytes to scan
            filename: Optional filename for context
            
        Returns:
            List of YARAMatch objects
        """
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(data=data)
            
            result = []
            for match in matches:
                # Extract matched strings
                matched_strings = []
                for string_name, string_data in match.strings.items():
                    matched_strings.append({
                        'id': string_name,
                        'string': string_data[0],
                        'offset': string_data[1],
                        'length': len(string_data[0]),
                    })
                
                result.append(YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace or 'default',
                    tags=match.tags or [],
                    meta=match.meta or {},
                    strings=matched_strings,
                ))
            
            return result
            
        except Exception as e:
            print(f"YARA scan error: {e}")
            return []