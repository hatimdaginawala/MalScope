#!/usr/bin/env python3
"""
MalScope Analysis Engine Worker

Entry point for the Python analysis engine.
Called by Node.js as a child process with CLI arguments.
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone

# Add the current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from static.pe_analyzer import PEAnalyzer
from common.result_formatter import ResultFormatter


def get_utc_iso():
    """Get current UTC time in ISO format"""
    return datetime.now(timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description='MalScope Analysis Engine')
    parser.add_argument(
        '--mode',
        choices=['static', 'dynamic', 'test'],
        required=True,
        help='Analysis mode to run'
    )
    parser.add_argument(
        '--sample',
        help='Path to the sample file (required for static mode)'
    )
    parser.add_argument(
        '--telemetry',
        help='Path to telemetry data (required for dynamic mode)'
    )
    parser.add_argument(
        '--output',
        help='Optional output path for results (defaults to stdout)'
    )

    args = parser.parse_args()

    # Prepare result structure
    result = {
        'success': True,
        'mode': args.mode,
        'timestamp': get_utc_iso(),
        'result': {},
        'warnings': [],
        'errors': []
    }

    try:
        if args.mode == 'test':
            # Simple test mode
            result['result'] = {
                'message': 'Python analysis engine is operational',
                'python_version': sys.version,
                'cwd': os.getcwd()
            }

        elif args.mode == 'static':
            if not args.sample:
                raise ValueError('--sample is required for static mode')
            if not os.path.exists(args.sample):
                raise FileNotFoundError(f'Sample not found: {args.sample}')

            # Initialize PE analyzer
            analyzer = PEAnalyzer()
            
            # Perform static analysis
            analysis_result = analyzer.analyze(args.sample)
            
            # Format results - this returns a dict with proper arrays
            formatted_result = ResultFormatter.to_dict(analysis_result)
            
            # ===== ENHANCED DEBUG OUTPUT =====
            # Print summary of extracted data
            print("=" * 50, file=sys.stderr)
            print(f"📊 Analysis Results for: {args.sample}", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            
            # File info
            file_info = formatted_result.get('file', {})
            if file_info:
                print(f"📄 File: {file_info.get('filename', 'Unknown')}", file=sys.stderr)
                print(f"   Size: {file_info.get('fileSize', 0)} bytes", file=sys.stderr)
                print(f"   Type: {file_info.get('fileType', 'Unknown')}", file=sys.stderr)
                print(f"   PE Type: {file_info.get('peType', 'Unknown')}", file=sys.stderr)
                print(f"   Architecture: {file_info.get('arch', 'Unknown')}", file=sys.stderr)
            
            # DOS Header
            dos_header = formatted_result.get('dosHeader')
            if dos_header:
                print(f"\n📋 DOS Header:", file=sys.stderr)
                print(f"   e_lfanew: {dos_header.get('e_lfanew', 0)}", file=sys.stderr)
            
            # COFF Header
            coff_header = formatted_result.get('coffHeader')
            if coff_header:
                print(f"\n📋 COFF Header:", file=sys.stderr)
                print(f"   Machine: {coff_header.get('machine', 'Unknown')}", file=sys.stderr)
                print(f"   Sections: {coff_header.get('numberOfSections', 0)}", file=sys.stderr)
                print(f"   Time Date Stamp: {coff_header.get('timeDateStamp', 'Unknown')}", file=sys.stderr)
                print(f"   Characteristics: {coff_header.get('characteristics', '')}", file=sys.stderr)
            
            # Optional Header
            optional_header = formatted_result.get('optionalHeader')
            if optional_header:
                print(f"\n📋 Optional Header:", file=sys.stderr)
                print(f"   Magic: {optional_header.get('magic', 'Unknown')}", file=sys.stderr)
                print(f"   Subsystem: {optional_header.get('subsystem', 'Unknown')}", file=sys.stderr)
                print(f"   Entry Point: {hex(optional_header.get('addressOfEntryPoint', 0))}", file=sys.stderr)
                print(f"   Image Base: {hex(optional_header.get('imageBase', 0))}", file=sys.stderr)
                print(f"   Size of Image: {optional_header.get('sizeOfImage', 0)}", file=sys.stderr)
                print(f"   Checksum: {optional_header.get('checksum', 0)}", file=sys.stderr)
                print(f"   DLL Characteristics: {hex(optional_header.get('dllCharacteristics', 0))}", file=sys.stderr)
            
            # Data Directories
            data_directories = formatted_result.get('dataDirectories', [])
            if data_directories:
                print(f"\n📋 Data Directories ({len(data_directories)}):", file=sys.stderr)
                for dir in data_directories[:5]:  # Show first 5
                    print(f"   - {dir.get('name', 'Unknown')}: VA: {hex(dir.get('virtualAddress', 0))}, Size: {dir.get('size', 0)}", file=sys.stderr)
                if len(data_directories) > 5:
                    print(f"   ... and {len(data_directories) - 5} more", file=sys.stderr)
            
            # Sections
            sections = formatted_result.get('sections', [])
            if sections:
                print(f"\n📋 Sections ({len(sections)}):", file=sys.stderr)
                for section in sections[:5]:
                    print(f"   - {section.get('name', 'Unknown')}: VA: {hex(section.get('virtualAddress', 0))}, Size: {section.get('rawSize', 0)}, Entropy: {section.get('entropy', 0):.2f}", file=sys.stderr)
                if len(sections) > 5:
                    print(f"   ... and {len(sections) - 5} more", file=sys.stderr)
            
            # Imports
            imports = formatted_result.get('imports', [])
            if imports:
                total_funcs = sum(len(imp.get('functions', [])) for imp in imports)
                print(f"\n📋 Imports: {len(imports)} DLLs, {total_funcs} functions", file=sys.stderr)
            
            # Strings
            strings = formatted_result.get('strings', {})
            if strings:
                ascii_count = len(strings.get('ascii', []))
                unicode_count = len(strings.get('unicode', []))
                suspicious_count = len(strings.get('suspicious', []))
                print(f"\n📋 Strings: {ascii_count} ASCII, {unicode_count} Unicode, {suspicious_count} Suspicious", file=sys.stderr)
                if suspicious_count > 0:
                    print(f"   Suspicious strings:", file=sys.stderr)
                    for s in strings.get('suspicious', [])[:5]:
                        print(f"     - {s[:100]}...", file=sys.stderr)
            
            # Entropy
            entropy = formatted_result.get('entropy', {})
            if entropy:
                print(f"\n📋 Entropy:", file=sys.stderr)
                print(f"   Overall: {entropy.get('overall', 0):.4f}", file=sys.stderr)
                high_entropy = entropy.get('highEntropySections', [])
                if high_entropy:
                    print(f"   High Entropy Sections: {', '.join(high_entropy)}", file=sys.stderr)
            
            # Resources
            resources = formatted_result.get('resources', [])
            if resources:
                print(f"\n📋 Resources: {len(resources)}", file=sys.stderr)
            
            # TLS
            tls = formatted_result.get('tls')
            if tls:
                print(f"\n🧵 TLS: Present", file=sys.stderr)
                print(f"   Start Address: {hex(tls.get('startAddressOfRawData', 0))}", file=sys.stderr)
                print(f"   End Address: {hex(tls.get('endAddressOfRawData', 0))}", file=sys.stderr)
            
            # Debug Info
            debug_info = formatted_result.get('debugInfo')
            if debug_info:
                print(f"\n🐛 Debug Info:", file=sys.stderr)
                print(f"   Type: {debug_info.get('type', 'Unknown')}", file=sys.stderr)
                if debug_info.get('pdbFilename'):
                    print(f"   PDB: {debug_info.get('pdbFilename')}", file=sys.stderr)
                if debug_info.get('guid'):
                    print(f"   GUID: {debug_info.get('guid')}", file=sys.stderr)
                if debug_info.get('age'):
                    print(f"   Age: {debug_info.get('age')}", file=sys.stderr)
            
            # Rich Header
            rich_header = formatted_result.get('richHeader')
            if rich_header:
                entries = rich_header.get('entries', [])
                print(f"\n📊 Rich Header:", file=sys.stderr)
                print(f"   Checksum: {rich_header.get('checksum', 0)}", file=sys.stderr)
                print(f"   Entries: {len(entries)}", file=sys.stderr)
                for entry in entries[:3]:
                    print(f"     - Product: {entry.get('productId', 0)}, Build: {entry.get('buildId', 0)}, Count: {entry.get('count', 0)}", file=sys.stderr)
                if len(entries) > 3:
                    print(f"     ... and {len(entries) - 3} more", file=sys.stderr)
            
            # Signature
            signature = formatted_result.get('signature')
            if signature:
                print(f"\n🔐 Digital Signature:", file=sys.stderr)
                print(f"   Signed: {signature.get('signed', False)}", file=sys.stderr)
                if signature.get('signed'):
                    print(f"   Signer: {signature.get('signer', 'Unknown')}", file=sys.stderr)
                    print(f"   Issuer: {signature.get('issuer', 'Unknown')}", file=sys.stderr)
                    if signature.get('validFrom'):
                        print(f"   Valid From: {signature.get('validFrom')}", file=sys.stderr)
                    if signature.get('validTo'):
                        print(f"   Valid To: {signature.get('validTo')}", file=sys.stderr)
                    print(f"   Algorithm: {signature.get('algorithm', 'Unknown')}", file=sys.stderr)
                    print(f"   Verification: {signature.get('verificationResult', 'Unknown')}", file=sys.stderr)
            
            # YARA
            yara_matches = formatted_result.get('yaraMatches', [])
            if yara_matches:
                print(f"\n🔍 YARA Matches: {len(yara_matches)}", file=sys.stderr)
                for match in yara_matches[:3]:
                    print(f"   - {match.get('ruleName', 'Unknown')}", file=sys.stderr)
                if len(yara_matches) > 3:
                    print(f"   ... and {len(yara_matches) - 3} more", file=sys.stderr)
            
            # Findings
            findings = formatted_result.get('findings', [])
            if findings:
                print(f"\n⚠️ Findings: {len(findings)}", file=sys.stderr)
                for finding in findings[:5]:
                    print(f"   - {finding.get('description', 'Unknown')} ({finding.get('severity', 'unknown')})", file=sys.stderr)
                if len(findings) > 5:
                    print(f"   ... and {len(findings) - 5} more", file=sys.stderr)
            
            # IOCs
            iocs = formatted_result.get('iocs', [])
            if iocs:
                print(f"\n📊 IOCs: {len(iocs)}", file=sys.stderr)
                # Group by type
                ioc_types = {}
                for ioc in iocs:
                    ioc_type = ioc.get('type', 'unknown')
                    ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
                for ioc_type, count in ioc_types.items():
                    print(f"   - {ioc_type}: {count}", file=sys.stderr)
            
            print("\n" + "=" * 50, file=sys.stderr)
            print(f"✅ Analysis completed successfully!", file=sys.stderr)
            print("=" * 50, file=sys.stderr)
            
            # Store formatted result
            result['result'] = formatted_result
            result['warnings'] = analysis_result.warnings
            result['errors'] = analysis_result.errors
            result['success'] = analysis_result.success

        elif args.mode == 'dynamic':
            if not args.telemetry:
                raise ValueError('--telemetry is required for dynamic mode')
            if not os.path.exists(args.telemetry):
                raise FileNotFoundError(f'Telemetry file not found: {args.telemetry}')

            # Placeholder - dynamic analysis will be implemented in Phase 10
            result['result'] = {
                'status': 'placeholder',
                'message': 'Dynamic analysis will be implemented in Phase 10',
                'telemetry_path': args.telemetry
            }
            result['warnings'].append('Dynamic analysis not yet implemented')

    except Exception as e:
        result['success'] = False
        result['errors'].append(str(e))
        print(f"❌ Error: {e}", file=sys.stderr)

    # Output results - ensure proper JSON serialization
    output_json = json.dumps(result, indent=2, default=str)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
    else:
        print(output_json)

    # Exit with appropriate code
    sys.exit(0 if result['success'] else 1)


if __name__ == '__main__':
    main()