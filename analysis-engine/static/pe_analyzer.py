"""
Complete PE analyzer orchestrating all analysis components
"""

import os
import hashlib
import pefile
import re
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


def get_utc_iso():
    """Get current UTC time in ISO format"""
    return datetime.now(timezone.utc).isoformat()


class PEAnalyzer:
    """Complete PE analyzer orchestrating all analysis"""
    
    def __init__(self):
        self.yara_analyzer = YARAAnalyzer()
    
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
                # Analyze sections
                result.sections = SectionAnalyzer.analyze(pe)
                
                # Analyze imports
                result.imports = ImportAnalyzer.analyze(pe)
                
                # Analyze exports
                result.exports = self._analyze_exports(pe)
                
                # Analyze strings
                result.strings = StringAnalyzer.analyze(pe)
                
                # Analyze entropy
                result.entropy = EntropyAnalyzer.analyze(pe)
                
                # Analyze resources
                result.resources = self._analyze_resources(pe)
                
                # YARA scan
                result.yara_matches = self.yara_analyzer.scan(file_path)
                
                # Generate findings
                result.findings = self._generate_findings(
                    file_info, result.imports, result.strings,
                    result.entropy, result.yara_matches
                )
                
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