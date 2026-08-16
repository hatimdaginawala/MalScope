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
            ioc_count = len(formatted_result.get('iocs', []))
            print(f"📊 IOCs in result: {ioc_count}", file=sys.stderr)
            
            # IMPORTANT: Ensure resources and findings are arrays, not strings
            if 'resources' in formatted_result:
                # If resources is a string, try to parse it
                if isinstance(formatted_result['resources'], str):
                    try:
                        formatted_result['resources'] = json.loads(formatted_result['resources'])
                    except:
                        formatted_result['resources'] = []
                # If it's already a list, keep it
                elif not isinstance(formatted_result['resources'], list):
                    formatted_result['resources'] = []
            
            if 'findings' in formatted_result:
                if isinstance(formatted_result['findings'], str):
                    try:
                        formatted_result['findings'] = json.loads(formatted_result['findings'])
                    except:
                        formatted_result['findings'] = []
                elif not isinstance(formatted_result['findings'], list):
                    formatted_result['findings'] = []
            
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