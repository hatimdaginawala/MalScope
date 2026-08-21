"""
API Intelligence - Classify imports into capability categories
"""

import json
import os
from typing import Dict, List, Set, Optional
from common.models import APICapability, APIAnalysisResult, ImportInfo


class APIIntelligence:
    """Classify imported APIs into capability categories"""
    
    def __init__(self):
        self.categories = {}
        self.api_to_category = {}
        self._load_categories()
    
    def _load_categories(self):
        """Load API categories from JSON file"""
        try:
            # Try to load from the JSON file
            json_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'common', 'api_categories.json'
            )
            
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            for category, info in data['categories'].items():
                apis = info.get('apis', [])
                self.categories[category] = APICapability(
                    category=category,
                    description=info.get('description', ''),
                    severity=info.get('severity', 'medium'),
                    apis=apis,
                )
                
                # Build reverse mapping
                for api in apis:
                    api_lower = api.lower()
                    if api_lower not in self.api_to_category:
                        self.api_to_category[api_lower] = []
                    self.api_to_category[api_lower].append(category)
        
        except Exception as e:
            print(f"Warning: Failed to load API categories: {e}")
            self._load_default_categories()
    
    def _load_default_categories(self):
        """Fallback: Load default categories if JSON fails"""
        self.categories = {
            'FILE': APICapability(
                category='FILE',
                description='File system operations',
                severity='medium',
                apis=['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'CopyFile', 'MoveFile']
            ),
            'PROCESS': APICapability(
                category='PROCESS',
                description='Process creation and manipulation',
                severity='high',
                apis=['CreateProcess', 'CreateRemoteThread', 'OpenProcess', 'TerminateProcess', 'WriteProcessMemory']
            ),
            'MEMORY': APICapability(
                category='MEMORY',
                description='Memory allocation and manipulation',
                severity='high',
                apis=['VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'HeapAlloc', 'HeapFree']
            ),
            'REGISTRY': APICapability(
                category='REGISTRY',
                description='Registry operations',
                severity='medium',
                apis=['RegCreateKeyEx', 'RegSetValueEx', 'RegOpenKeyEx', 'RegQueryValueEx', 'RegDeleteKey']
            ),
            'NETWORK': APICapability(
                category='NETWORK',
                description='Network communication',
                severity='high',
                apis=['InternetOpen', 'InternetConnect', 'HttpOpenRequest', 'WinHttpOpen', 'socket']
            ),
            'CRYPTO': APICapability(
                category='CRYPTO',
                description='Cryptographic operations',
                severity='medium',
                apis=['CryptAcquireContext', 'CryptGenKey', 'CryptEncrypt', 'CryptDecrypt']
            ),
            'PERSISTENCE': APICapability(
                category='PERSISTENCE',
                description='Persistence mechanisms',
                severity='high',
                apis=['CreateService', 'StartService', 'RegSetValueEx', 'SetWindowsHookEx', 'ShellExecute']
            ),
            'ANTI_ANALYSIS': APICapability(
                category='ANTI_ANALYSIS',
                description='Anti-debugging and anti-analysis',
                severity='high',
                apis=['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess']
            ),
        }
        
        # Build reverse mapping
        for category, cap in self.categories.items():
            for api in cap.apis:
                api_lower = api.lower()
                if api_lower not in self.api_to_category:
                    self.api_to_category[api_lower] = []
                self.api_to_category[api_lower].append(category)
    
    def classify_imports(self, imports: List[ImportInfo]) -> APIAnalysisResult:
        """
        Classify imports into capability categories
        
        Args:
            imports: List of ImportInfo objects
            
        Returns:
            APIAnalysisResult with category classifications
        """
        categories = {}
        total_apis = 0
        
        # Track which APIs were found in each category
        for category in self.categories.keys():
            categories[category] = []
        
        # Process each import
        for imp in imports:
            dll = imp.dll.lower()
            for func in imp.functions:
                func_lower = func.lower()
                total_apis += 1
                
                # Check if this API belongs to any category
                if func_lower in self.api_to_category:
                    for category in self.api_to_category[func_lower]:
                        if func not in categories.get(category, []):
                            categories[category].append(func)
        
        # Filter out empty categories
        non_empty_categories = {
            cat: apis for cat, apis in categories.items() 
            if apis and len(apis) > 0
        }
        
        # Calculate severity summary
        severity_summary = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        for category, apis in non_empty_categories.items():
            if category in self.categories:
                severity = self.categories[category].severity
                severity_summary[severity] = severity_summary.get(severity, 0) + len(apis)
        
        # Get top categories (by number of APIs)
        top_categories = sorted(
            [{'category': cat, 'count': len(apis), 'apis': apis[:5]} 
             for cat, apis in non_empty_categories.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:5]
        
        return APIAnalysisResult(
            categories=non_empty_categories,
            total_apis=total_apis,
            total_categories=len(non_empty_categories),
            severity_summary=severity_summary,
            top_categories=top_categories,
        )
    
    def get_capability_summary(self, result: APIAnalysisResult) -> Dict:
        """
        Get a summary of capabilities for display
        
        Args:
            result: APIAnalysisResult
            
        Returns:
            Dictionary with summary information
        """
        return {
            'total_apis': result.total_apis,
            'total_categories': result.total_categories,
            'categories': result.categories,
            'severity_summary': result.severity_summary,
            'top_categories': result.top_categories,
            'capabilities': [
                {
                    'category': cat,
                    'description': self.categories.get(cat, APICapability(cat, '', 'medium', [])).description,
                    'severity': self.categories.get(cat, APICapability(cat, '', 'medium', [])).severity,
                    'apis': apis[:10],
                    'count': len(apis),
                }
                for cat, apis in result.categories.items()
            ]
        }
    
    def find_high_risk_apis(self, result: APIAnalysisResult) -> List[Dict]:
        """
        Find high-risk APIs in the imports
        
        Args:
            result: APIAnalysisResult
            
        Returns:
            List of high-risk APIs with details
        """
        high_risk = []
        
        for category, apis in result.categories.items():
            if category in self.categories:
                severity = self.categories[category].severity
                if severity in ['high', 'critical']:
                    for api in apis:
                        high_risk.append({
                            'api': api,
                            'category': category,
                            'severity': severity,
                            'description': self.categories[category].description,
                        })
        
        return high_risk
    
    def get_category_for_api(self, api_name: str) -> List[str]:
        """
        Get categories for a specific API
        
        Args:
            api_name: Name of the API
            
        Returns:
            List of categories
        """
        api_lower = api_name.lower()
        return self.api_to_category.get(api_lower, [])