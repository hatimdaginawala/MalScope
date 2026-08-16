"""
Result formatter for converting analysis results to JSON
"""

import json
from typing import Any, Dict
from common.models import StaticAnalysisResult


class ResultFormatter:
    """Format analysis results for Node.js consumption"""
    
    @staticmethod
    def to_dict(result: StaticAnalysisResult) -> Dict[str, Any]:
        """Convert result to dictionary for JSON serialization"""
        
        # Convert file info
        file_info = None
        if result.file_info:
            file_info = {
                'filename': result.file_info.filename,
                'fileSize': result.file_info.file_size,
                'fileType': result.file_info.file_type,
                'mimeType': result.file_info.mime_type,
                'peType': result.file_info.pe_type,
                'arch': result.file_info.arch,
                'compileTime': result.file_info.compile_time,
                'linkerVersion': result.file_info.linker_version,
                'entryPoint': result.file_info.entry_point,
                'imageBase': result.file_info.image_base,
                'subsystem': result.file_info.subsystem,
            }
        
        # Convert sections - always return list
        sections = []
        if result.sections:
            for section in result.sections:
                sections.append({
                    'name': section.name,
                    'virtualAddress': section.virtual_address,
                    'virtualSize': section.virtual_size,
                    'rawSize': section.raw_size,
                    'characteristics': section.characteristics,
                    'entropy': section.entropy,
                })
        
        # Convert imports - always return list
        imports = []
        if result.imports:
            for imp in result.imports:
                imports.append({
                    'dll': imp.dll,
                    'functions': imp.functions,
                })
        
        # Convert exports - always return list
        exports = []
        if result.exports:
            for exp in result.exports:
                exports.append({
                    'name': exp.name,
                    'ordinal': exp.ordinal,
                    'address': exp.address,
                })
        
        # Convert strings
        strings = None
        if result.strings:
            strings = {
                'ascii': result.strings.ascii or [],
                'unicode': result.strings.unicode or [],
                'suspicious': result.strings.suspicious or [],
            }
        
        # Convert entropy
        entropy = None
        if result.entropy:
            entropy = {
                'overall': result.entropy.overall,
                'sections': result.entropy.sections or [],
                'highEntropySections': result.entropy.high_entropy_sections or [],
            }
        
        # Convert resources - ALWAYS return a list
        resources = []
        if result.resources:
            for resource in result.resources:
                if isinstance(resource, dict):
                    resources.append(resource)
                else:
                    resources.append({
                        'type': getattr(resource, 'type', ''),
                        'id': getattr(resource, 'id', 0),
                        'language': getattr(resource, 'language', 0),
                        'size': getattr(resource, 'size', 0),
                        'sha256': getattr(resource, 'sha256', ''),
                    })
        
        # Convert YARA matches - always return list
        yara_matches = []
        if result.yara_matches:
            for match in result.yara_matches:
                yara_matches.append({
                    'ruleName': match.rule_name,
                    'namespace': match.namespace,
                    'tags': match.tags or [],
                    'meta': match.meta or {},
                    'strings': match.strings or [],
                })
        
        # Convert findings - ALWAYS return a list
        findings = []
        if result.findings:
            for finding in result.findings:
                if isinstance(finding, dict):
                    findings.append(finding)
                else:
                    findings.append({
                        'type': getattr(finding, 'type', ''),
                        'severity': getattr(finding, 'severity', 'low'),
                        'description': getattr(finding, 'description', ''),
                        'evidence': getattr(finding, 'evidence', ''),
                        'confidence': getattr(finding, 'confidence', 0.5),
                    })
        
        # Convert IOCs - always return list
        iocs = []
        if result.iocs:
            for ioc in result.iocs:
                iocs.append({
                    'type': ioc.type,
                    'value': ioc.value,
                    'confidence': ioc.confidence,
                    'context': ioc.context or {},
                })
        
        return {
            'success': result.success,
            'timestamp': result.timestamp,
            'file': file_info,
            'sections': sections,
            'imports': imports,
            'exports': exports,
            'strings': strings,
            'entropy': entropy,
            'resources': resources,
            'yaraMatches': yara_matches,
            'findings': findings,
            'iocs': iocs,
            'warnings': result.warnings or [],
            'errors': result.errors or [],
        }
    
    @staticmethod
    def to_json(result: StaticAnalysisResult) -> str:
        """Convert result to JSON string"""
        return json.dumps(ResultFormatter.to_dict(result), indent=2)