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
        
        # Convert DOS header
        dos_header = None
        if result.dos_header:
            dos_header = {
                'magic': result.dos_header.magic,
                'e_cblp': result.dos_header.e_cblp,
                'e_cp': result.dos_header.e_cp,
                'e_crlc': result.dos_header.e_crlc,
                'e_cparhdr': result.dos_header.e_cparhdr,
                'e_minalloc': result.dos_header.e_minalloc,
                'e_maxalloc': result.dos_header.e_maxalloc,
                'e_ss': result.dos_header.e_ss,
                'e_sp': result.dos_header.e_sp,
                'e_csum': result.dos_header.e_csum,
                'e_ip': result.dos_header.e_ip,
                'e_cs': result.dos_header.e_cs,
                'e_lfarlc': result.dos_header.e_lfarlc,
                'e_ovno': result.dos_header.e_ovno,
                'e_res': result.dos_header.e_res,
                'e_oemid': result.dos_header.e_oemid,
                'e_oeminfo': result.dos_header.e_oeminfo,
                'e_res2': result.dos_header.e_res2,
                'e_lfanew': result.dos_header.e_lfanew,
            }
        
        # Convert COFF header
        coff_header = None
        if result.coff_header:
            coff_header = {
                'machine': result.coff_header.machine,
                'numberOfSections': result.coff_header.number_of_sections,
                'timeDateStamp': result.coff_header.time_date_stamp,
                'pointerToSymbolTable': result.coff_header.pointer_to_symbol_table,
                'numberOfSymbols': result.coff_header.number_of_symbols,
                'sizeOfOptionalHeader': result.coff_header.size_of_optional_header,
                'characteristics': result.coff_header.characteristics,
            }
        
        # Convert Optional header
        optional_header = None
        if result.optional_header:
            optional_header = {
                'magic': result.optional_header.magic,
                'majorLinkerVersion': result.optional_header.major_linker_version,
                'minorLinkerVersion': result.optional_header.minor_linker_version,
                'sizeOfCode': result.optional_header.size_of_code,
                'sizeOfInitializedData': result.optional_header.size_of_initialized_data,
                'sizeOfUninitializedData': result.optional_header.size_of_uninitialized_data,
                'addressOfEntryPoint': result.optional_header.address_of_entry_point,
                'baseOfCode': result.optional_header.base_of_code,
                'baseOfData': result.optional_header.base_of_data,
                'imageBase': result.optional_header.image_base,
                'sectionAlignment': result.optional_header.section_alignment,
                'fileAlignment': result.optional_header.file_alignment,
                'majorOperatingSystemVersion': result.optional_header.major_operating_system_version,
                'minorOperatingSystemVersion': result.optional_header.minor_operating_system_version,
                'majorImageVersion': result.optional_header.major_image_version,
                'minorImageVersion': result.optional_header.minor_image_version,
                'majorSubsystemVersion': result.optional_header.major_subsystem_version,
                'minorSubsystemVersion': result.optional_header.minor_subsystem_version,
                'win32VersionValue': result.optional_header.win32_version_value,
                'sizeOfImage': result.optional_header.size_of_image,
                'sizeOfHeaders': result.optional_header.size_of_headers,
                'checksum': result.optional_header.checksum,
                'subsystem': result.optional_header.subsystem,
                'dllCharacteristics': result.optional_header.dll_characteristics,
                'sizeOfStackReserve': result.optional_header.size_of_stack_reserve,
                'sizeOfStackCommit': result.optional_header.size_of_stack_commit,
                'sizeOfHeapReserve': result.optional_header.size_of_heap_reserve,
                'sizeOfHeapCommit': result.optional_header.size_of_heap_commit,
                'loaderFlags': result.optional_header.loader_flags,
                'numberOfRvaAndSizes': result.optional_header.number_of_rva_and_sizes,
            }
        
        # Convert data directories
        data_directories = []
        for dir in result.data_directories:
            data_directories.append({
                'name': dir.name,
                'virtualAddress': dir.virtual_address,
                'size': dir.size,
            })
        
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
        
        # Convert TLS
        tls = None
        if result.tls:
            tls = {
                'startAddressOfRawData': result.tls.start_address_of_raw_data,
                'endAddressOfRawData': result.tls.end_address_of_raw_data,
                'addressOfIndex': result.tls.address_of_index,
                'addressOfCallbacks': result.tls.address_of_callbacks,
                'sizeOfZeroFill': result.tls.size_of_zero_fill,
                'characteristics': result.tls.characteristics,
            }
        
        # Convert Debug info
        debug_info = None
        if result.debug_info:
            debug_info = {
                'type': result.debug_info.type,
                'age': result.debug_info.age,
                'guid': result.debug_info.guid,
                'pdbFilename': result.debug_info.pdb_filename,
            }
        
        # Convert Rich header
        rich_header = None
        if result.rich_header:
            rich_header = {
                'checksum': result.rich_header.checksum,
                'entries': [
                    {
                        'productId': entry.product_id,
                        'buildId': entry.build_id,
                        'count': entry.count,
                    } for entry in result.rich_header.entries
                ],
            }
        
        # Convert Signature
        signature = None
        if result.signature:
            signature = {
                'signed': result.signature.signed,
                'signer': result.signature.signer,
                'issuer': result.signature.issuer,
                'serialNumber': result.signature.serial_number,
                'validFrom': result.signature.valid_from,
                'validTo': result.signature.valid_to,
                'algorithm': result.signature.algorithm,
                'timestamp': result.signature.timestamp,
                'verificationResult': result.signature.verification_result,
                'certificateChain': result.signature.certificate_chain,
            }
        
        # ===== NEW: Convert API Intelligence =====
        api_intelligence = None
        if hasattr(result, 'api_intelligence') and result.api_intelligence:
            api_intelligence = {
                'total_apis': result.api_intelligence.get('total_apis', 0),
                'total_categories': result.api_intelligence.get('total_categories', 0),
                'categories': result.api_intelligence.get('categories', {}),
                'severity_summary': result.api_intelligence.get('severity_summary', {}),
                'top_categories': result.api_intelligence.get('top_categories', []),
                'capabilities': result.api_intelligence.get('capabilities', []),
            }
        
        # ===== NEW: Convert High Risk APIs =====
        high_risk_apis = []
        if hasattr(result, 'high_risk_apis') and result.high_risk_apis:
            high_risk_apis = result.high_risk_apis
        
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
            'dosHeader': dos_header,
            'coffHeader': coff_header,
            'optionalHeader': optional_header,
            'dataDirectories': data_directories,
            'sections': sections,
            'imports': imports,
            'exports': exports,
            'strings': strings,
            'entropy': entropy,
            'resources': resources,
            'tls': tls,
            'debugInfo': debug_info,
            'richHeader': rich_header,
            'signature': signature,
            # ===== NEW: API Intelligence fields =====
            'apiIntelligence': api_intelligence,
            'highRiskApis': high_risk_apis,
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