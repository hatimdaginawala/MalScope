"""
String Intelligence - Classify strings into categories
"""

import json
import os
import re
from typing import List, Dict, Set, Optional

# Import from common.models
from common.models import ClassifiedString, StringIntelligenceResult


class StringIntelligence:
    """Classify extracted strings into meaningful categories"""
    
    def __init__(self):
        self.patterns = {}
        self._load_patterns()
    
    def _load_patterns(self):
        """Load string patterns from JSON file"""
        try:
            json_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'common', 'string_patterns.json'
            )
            
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            self.patterns = data.get('patterns', {})
            
        except Exception as e:
            print(f"Warning: Failed to load string patterns: {e}")
            self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Fallback: Load default patterns"""
        self.patterns = {
            'url': {
                'description': 'URL patterns',
                'severity': 'medium',
                'regex': [r'https?://[^\s<>"'"'"']+']
            },
            'domain': {
                'description': 'Domain names',
                'severity': 'medium',
                'regex': [r'[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}']
            },
            'ipv4': {
                'description': 'IPv4 addresses',
                'severity': 'high',
                'regex': [r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b']
            },
            'file_path': {
                'description': 'Windows file paths',
                'severity': 'low',
                'regex': [r'[A-Za-z]:\\[^\\\s<>"'"'"']+\\[^\\\s<>"'"'"']+']
            },
            'registry_path': {
                'description': 'Windows registry paths',
                'severity': 'medium',
                'regex': [r'[A-Za-z_][A-Za-z0-9_]*\\[A-Za-z_][A-Za-z0-9_]*\\[A-Za-z_][A-Za-z0-9_]*']
            },
            'command': {
                'description': 'Command execution patterns',
                'severity': 'high',
                'regex': [r'cmd\.exe', r'powershell\.exe', r'wscript\.exe', r'cscript\.exe']
            },
            'mutex': {
                'description': 'Mutex-like strings',
                'severity': 'low',
                'regex': [r'Global\\[A-Za-z0-9_\-]+', r'Local\\[A-Za-z0-9_\-]+']
            },
            'suspicious': {
                'description': 'Suspicious string patterns',
                'severity': 'high',
                'regex': [r'\b(?:ransom|encrypt|decrypt|steal|keylog|hack|exploit|malware|trojan|virus)\b']
            },
            'email': {
                'description': 'Email addresses',
                'severity': 'low',
                'regex': [r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}']
            }
        }
    
    def classify_strings(self, strings: List[str]) -> StringIntelligenceResult:
        """
        Classify strings into categories
        
        Args:
            strings: List of strings to classify
            
        Returns:
            StringIntelligenceResult with classified strings
        """
        classified = []
        seen = set()
        category_counts = {}
        severity_summary = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        ioc_candidates = []
        
        # Initialize category counts
        for category in self.patterns.keys():
            category_counts[category] = 0
        
        # Process each string
        for string_value in strings:
            if not string_value or len(string_value) < 3:
                continue
            
            # Normalize for deduplication
            normalized = string_value.lower().strip()
            if normalized in seen:
                continue
            seen.add(normalized)
            
            # Check against patterns
            matches = self._match_patterns(string_value)
            
            if matches:
                # Classify by highest severity match
                primary_match = max(matches, key=lambda m: self._severity_score(m['severity']))
                
                classified_string = ClassifiedString(
                    value=string_value[:500],
                    category=primary_match['category'],
                    severity=primary_match['severity'],
                    evidence=primary_match['evidence'],
                    confidence=0.8 if len(primary_match['matches']) > 1 else 0.6,
                )
                classified.append(classified_string)
                
                # Update counts
                category_counts[primary_match['category']] = category_counts.get(primary_match['category'], 0) + 1
                severity_summary[primary_match['severity']] = severity_summary.get(primary_match['severity'], 0) + 1
                
                # Check if this is an IOC candidate (high severity)
                if primary_match['severity'] in ['high', 'critical']:
                    ioc_candidates.append(classified_string)
        
        return StringIntelligenceResult(
            total_strings=len(strings),
            classified_strings=classified,
            category_counts=category_counts,
            suspicious_count=category_counts.get('suspicious', 0),
            ioc_candidates=ioc_candidates,
            severity_summary=severity_summary,
        )
    
    def _match_patterns(self, string_value: str) -> List[Dict]:
        """Match string against all patterns"""
        matches = []
        
        for category, pattern_info in self.patterns.items():
            regexes = pattern_info.get('regex', [])
            severity = pattern_info.get('severity', 'medium')
            description = pattern_info.get('description', '')
            
            for regex in regexes:
                try:
                    if re.search(regex, string_value, re.IGNORECASE):
                        matches.append({
                            'category': category,
                            'severity': severity,
                            'evidence': description,
                            'matches': [string_value[:100]],
                        })
                        break
                except re.error:
                    continue
        
        return matches
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity to numeric score for sorting"""
        scores = {
            'low': 0,
            'medium': 1,
            'high': 2,
            'critical': 3,
        }
        return scores.get(severity, 0)
    
    def get_summary(self, result: StringIntelligenceResult) -> Dict:
        """Get summary of string intelligence results"""
        return {
            'total_strings': result.total_strings,
            'classified_count': len(result.classified_strings),
            'category_counts': result.category_counts,
            'suspicious_count': result.suspicious_count,
            'ioc_candidates': len(result.ioc_candidates),
            'severity_summary': result.severity_summary,
            'top_categories': sorted(
                [(cat, count) for cat, count in result.category_counts.items() if count > 0],
                key=lambda x: x[1],
                reverse=True
            )[:5],
        }