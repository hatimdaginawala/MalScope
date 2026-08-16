"""
Result formatter for converting analysis results to JSON
"""

import json
from datetime import datetime
from typing import Any, Dict
from .models import StaticAnalysisResult


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
        
        # Convert sections
        sections = []
        for section in result.sections:
            sections.append({
                'name': section.name,
                'virtualAddress': section.virtual_address,
                'virtualSize': section.virtual_size,
                'rawSize': section.raw_size,
                'characteristics': section.characteristics,
                'entropy': section.entropy,
            })
        
        # Convert imports
        imports = []
        for imp in result.imports:
            imports.append({
                'dll': imp.dll,
                'functions': imp.functions,
            })
        
        # Convert exports
        exports = []
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
                'ascii': result.strings.ascii,
                'unicode': result.strings.unicode,
                'suspicious': result.strings.suspicious,
            }
        
        # Convert entropy
        entropy = None
        if result.entropy:
            entropy = {
                'overall': result.entropy.overall,
                'sections': result.entropy.sections,
                'highEntropySections': result.entropy.high_entropy_sections,
            }
        
        # Convert resources
        resources = []
        for resource in result.resources:
            resources.append({
                'type': resource.type,
                'id': resource.id,
                'language': resource.language,
                'size': resource.size,
                'sha256': resource.sha256,
            })
        
        # Convert YARA matches
        yara_matches = []
        for match in result.yara_matches:
            yara_matches.append({
                'ruleName': match.rule_name,
                'namespace': match.namespace,
                'tags': match.tags,
                'meta': match.meta,
                'strings': match.strings,
            })
        
        # Convert findings
        findings = []
        for finding in result.findings:
            findings.append({
                'type': finding.type,
                'severity': finding.severity,
                'description': finding.description,
                'evidence': finding.evidence,
                'confidence': finding.confidence,
            })
        
        # Convert IOCs
        iocs = []
        for ioc in result.iocs:
            iocs.append({
                'type': ioc.type,
                'value': ioc.value,
                'confidence': ioc.confidence,
                'context': ioc.context,
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
            'warnings': result.warnings,
            'errors': result.errors,
        }
    
    @staticmethod
    def to_json(result: StaticAnalysisResult) -> str:
        """Convert result to JSON string"""
        return json.dumps(ResultFormatter.to_dict(result), indent=2)