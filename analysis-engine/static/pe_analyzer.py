"""
Complete PE analyzer orchestrating all analysis components
"""

import os
import hashlib
import pefile
import re
import sys
from typing import Dict, Any, List
from datetime import datetime, timezone

# Use absolute imports
from common.models import (
    StaticAnalysisResult, PEInfo, SectionInfo, ImportInfo,
    ExportInfo, StringInfo, EntropyInfo, ResourceInfo,
    YARAMatch, Finding, IOC
)
from static.file_analyzer import FileAnalyzer
from static.hash_analyzer import HashAnalyzer
from static.section_analyzer import SectionAnalyzer
from static.import_analyzer import ImportAnalyzer
from static.entropy_analyzer import EntropyAnalyzer
from static.string_analyzer import StringAnalyzer
from static.yara_analyzer import YARAAnalyzer
from static.api_intelligence import APIIntelligence
from static.string_intelligence import StringIntelligence

# NEW imports
from static.header_analyzer import HeaderAnalyzer
from static.tls_analyzer import TLSAnalyzer
from static.debug_analyzer import DebugAnalyzer
from static.rich_header_analyzer import RichHeaderAnalyzer
from static.signature_analyzer import SignatureAnalyzer


def get_utc_iso():
    """Get current UTC time in ISO format"""
    return datetime.now(timezone.utc).isoformat()


class PEAnalyzer:
    """Complete PE analyzer orchestrating all analysis"""
    
    def __init__(self):
        self.yara_analyzer = YARAAnalyzer()
        self.api_intelligence = APIIntelligence()
        self.string_intelligence = StringIntelligence()
    
    def analyze(self, file_path: str) -> StaticAnalysisResult:
        """
        Perform complete static analysis on a PE file
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            StaticAnalysisResult object
        """
        result = StaticAnalysisResult(
            success=False,
            timestamp=get_utc_iso(),
        )
        
        try:
            # Check file exists
            if not os.path.exists(file_path):
                result.errors.append(f"File not found: {file_path}")
                return result
            
            # Calculate hashes
            try:
                hashes = HashAnalyzer.calculate_hashes(file_path)
            except Exception as e:
                result.warnings.append(f"Hash calculation failed: {e}")
                hashes = {}
            
            # Analyze file info
            try:
                file_info = FileAnalyzer.analyze(file_path)
                result.file_info = file_info
            except Exception as e:
                result.errors.append(f"File analysis failed: {e}")
                return result
            
            # Parse PE
            pe = None
            try:
                pe = pefile.PE(file_path)
            except pefile.PEFormatError:
                result.errors.append("Invalid PE file")
                result.success = False
                return result
            except Exception as e:
                result.errors.append(f"PE parsing failed: {e}")
                result.success = False
                return result
            
            try:
                # Header Analysis
                result.dos_header = HeaderAnalyzer.analyze_dos_header(pe)
                result.coff_header = HeaderAnalyzer.analyze_coff_header(pe)
                result.optional_header = HeaderAnalyzer.analyze_optional_header(pe)
                result.data_directories = HeaderAnalyzer.analyze_data_directories(pe)
                
                # Analyze sections
                result.sections = SectionAnalyzer.analyze(pe)
                
                # Analyze imports
                result.imports = ImportAnalyzer.analyze(pe)
                
                # Analyze exports
                result.exports = self._analyze_exports(pe)
                
                # Analyze strings
                result.strings = StringAnalyzer.analyze(pe)
                
                # ===== NEW: String Intelligence =====
                all_strings = []
                if result.strings:
                    all_strings.extend(result.strings.ascii[:1000])
                    all_strings.extend(result.strings.unicode[:500])
                
                if all_strings:
                    string_intel_result = self.string_intelligence.classify_strings(all_strings)
                    result.string_intelligence = self.string_intelligence.get_summary(string_intel_result)
                    
                    # Add findings for suspicious strings
                    if string_intel_result.suspicious_count > 0:
                        result.findings.append(Finding(
                            type='suspicious_strings_detected',
                            severity='medium',
                            description=f"Found {string_intel_result.suspicious_count} suspicious strings",
                            evidence=f"Suspicious strings found in {len(set(s.category for s in string_intel_result.classified_strings if s.category == 'suspicious'))} categories",
                            confidence=0.7,
                        ))
                    
                    # Add findings for high severity strings (IOC candidates)
                    high_severity_strings = [s for s in string_intel_result.classified_strings if s.severity in ['high', 'critical']]
                    if high_severity_strings:
                        categories = {}
                        for s in high_severity_strings[:10]:
                            categories[s.category] = categories.get(s.category, 0) + 1
                        
                        category_str = ', '.join([f"{cat} ({count})" for cat, count in categories.items()])
                        result.findings.append(Finding(
                            type='high_severity_strings',
                            severity='high',
                            description=f"Found {len(high_severity_strings)} high-severity strings",
                            evidence=f"Categories: {category_str}",
                            confidence=0.8,
                        ))
                
                # Analyze entropy
                result.entropy = EntropyAnalyzer.analyze(pe)
                
                # Analyze resources
                result.resources = self._analyze_resources(pe)
                
                # TLS Analysis
                result.tls = TLSAnalyzer.analyze(pe)
                
                # Debug Information
                result.debug_info = DebugAnalyzer.analyze(pe)
                
                # Rich Header
                result.rich_header = RichHeaderAnalyzer.analyze(pe)
                
                # Digital Signature
                result.signature = SignatureAnalyzer.analyze(pe)
                
                # YARA scan
                result.yara_matches = self.yara_analyzer.scan(file_path)
                
                # ===== API Intelligence =====
                api_result = self.api_intelligence.classify_imports(result.imports)
                result.api_intelligence = self.api_intelligence.get_capability_summary(api_result)
                result.high_risk_apis = self.api_intelligence.find_high_risk_apis(api_result)
                
                # Add findings from API intelligence
                if api_result.total_categories > 0:
                    for category, apis in api_result.categories.items():
                        if len(apis) > 0:
                            cat_info = self.api_intelligence.categories.get(category)
                            if cat_info:
                                severity = cat_info.severity
                            else:
                                severity = 'medium'
                            
                            result.findings.append(Finding(
                                type='api_capability',
                                severity=severity,
                                description=f"API indicators for {category.lower().replace('_', ' ')} capability",
                                evidence=f"Found {len(apis)} APIs related to {category.lower().replace('_', ' ')}: {', '.join(apis[:3])}",
                                confidence=0.8 if len(apis) > 3 else 0.6,
                            ))
                
                # Generate other findings
                result.findings.extend(self._generate_findings(
                    file_info, result.imports, result.strings,
                    result.entropy, result.yara_matches
                ))
                
                # Extract IOCs
                result.iocs = self._extract_iocs(
                    file_info, result.strings, result.findings,
                    hashes
                )
                
                result.success = True
                
            except Exception as e:
                result.errors.append(f"Analysis failed: {e}")
                result.success = False
            
            finally:
                if pe:
                    pe.close()
            
            return result
            
        except Exception as e:
            result.errors.append(f"Unexpected error: {e}")
            result.success = False
            return result
    
    def _analyze_exports(self, pe: pefile.PE) -> List[ExportInfo]:
        """Analyze PE exports"""
        exports = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports
        
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            exports.append(ExportInfo(
                name=exp.name.decode('utf-8') if exp.name else f"Ordinal_{exp.ordinal}",
                ordinal=exp.ordinal,
                address=exp.address,
            ))
        
        return exports
    
    def _analyze_resources(self, pe: pefile.PE) -> List[ResourceInfo]:
        """Analyze PE resources"""
        resources = []
        
        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return resources
        
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for resource_id in resource_type.directory.entries:
                for resource_lang in resource_id.directory.entries:
                    try:
                        data = pe.get_data(
                            resource_lang.data.struct.OffsetToData,
                            resource_lang.data.struct.Size
                        )
                        
                        resources.append(ResourceInfo(
                            type=pefile.RESOURCE_TYPE.get(
                                resource_type.struct.Id, f"Type_{resource_type.struct.Id}"
                            ),
                            id=resource_id.struct.Id,
                            language=resource_lang.struct.Id,
                            size=len(data),
                            sha256=hashlib.sha256(data).hexdigest(),
                        ))
                    except:
                        pass
        
        return resources
    
    def _generate_findings(self, file_info: PEInfo, imports: List[ImportInfo],
                          strings: StringInfo, entropy: EntropyInfo,
                          yara_matches: List[YARAMatch]) -> List[Finding]:
        """Generate findings from analysis results"""
        findings = []
        
        # Check for suspicious imports
        suspicious_imports = ImportAnalyzer.get_suspicious_imports(imports)
        if suspicious_imports:
            findings.append(Finding(
                type='suspicious_import',
                severity='medium',
                description=f"Contains suspicious API imports: {', '.join(suspicious_imports[:5])}",
                evidence=f"Found {len(suspicious_imports)} suspicious imports",
                confidence=0.7,
            ))
        
        # Check for suspicious strings
        if strings and strings.suspicious:
            findings.append(Finding(
                type='suspicious_strings',
                severity='medium',
                description="Contains suspicious strings",
                evidence=f"Found {len(strings.suspicious)} suspicious strings",
                confidence=0.6,
            ))
        
        # Check for high entropy (potential packing/encryption)
        if entropy and entropy.high_entropy_sections:
            findings.append(Finding(
                type='high_entropy',
                severity='medium',
                description=f"High entropy sections detected: {', '.join(entropy.high_entropy_sections[:3])}",
                evidence=f"Found {len(entropy.high_entropy_sections)} high entropy sections",
                confidence=0.5,
            ))
        
        # Check YARA matches
        if yara_matches:
            for match in yara_matches:
                severity = 'high' if 'malware' in match.rule_name.lower() else 'medium'
                findings.append(Finding(
                    type='yara_match',
                    severity=severity,
                    description=f"YARA rule match: {match.rule_name}",
                    evidence=f"Rule: {match.rule_name}, Tags: {', '.join(match.tags)}",
                    confidence=0.9 if 'malware' in match.rule_name.lower() else 0.7,
                ))
        
        return findings
    
    def _extract_iocs(self, file_info: PEInfo, strings: StringInfo,
                     findings: List[Finding], hashes: Dict[str, str]) -> List[IOC]:
        """Extract IOCs from analysis results"""
        iocs = []
        
        # Add hashes as IOCs
        if hashes.get('sha256'):
            iocs.append(IOC(
                type='sha256',
                value=hashes['sha256'],
                confidence=1.0,
                context={'source': 'hash_calculation'},
            ))
        if hashes.get('md5'):
            iocs.append(IOC(
                type='md5',
                value=hashes['md5'],
                confidence=1.0,
                context={'source': 'hash_calculation'},
            ))
        
        # Extract IPs from strings
        if strings:
            all_strings = strings.ascii + strings.unicode
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            
            for s in all_strings:
                ips = re.findall(ip_pattern, s)
                for ip in ips:
                    if ip not in [i.value for i in iocs if i.type == 'ip']:
                        iocs.append(IOC(
                            type='ip',
                            value=ip,
                            confidence=0.6,
                            context={'source': 'string_analysis'},
                        ))
            
            # Extract domains
            domain_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'
            for s in all_strings:
                domains = re.findall(domain_pattern, s)
                for domain in domains:
                    if domain not in [i.value for i in iocs if i.type == 'domain']:
                        iocs.append(IOC(
                            type='domain',
                            value=domain,
                            confidence=0.5,
                            context={'source': 'string_analysis'},
                        ))
        
        return iocs