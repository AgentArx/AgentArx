#!/usr/bin/env python3
"""
AgentArx - Automated Security Testing Framework
Main entry point for executing security assessments using LLM agents
"""

import sys
import argparse
from pathlib import Path
from .orchestrator import AgentArxOrchestrator
from .config.settings import settings


def setup_arguments() -> argparse.ArgumentParser:
    """Setup command line arguments"""
    parser = argparse.ArgumentParser(
        description='AgentArx - Automated Security Testing Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --file attack.json
  python main.py --file attack.json --export-findings
  python main.py --file attack.json --start-from analysis
  python main.py --test-config
        """
    )
    
    # Input options
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Execute attack definition JSON file'
    )
    
    # Output options
    parser.add_argument(
        '--export-findings',
        action='store_true',
        help='Export results to configured vulnerability tracker'
    )
    
    parser.add_argument(
        '--start-from',
        choices=['analysis', 'attack', 'report'],
        help='Start from a specific phase using previously saved results (skips earlier phases)'
    )
    
    parser.add_argument(
        '--test-config',
        action='store_true',
        help='Test configuration and connections'
    )
    
    return parser


def test_configuration():
    """Test system configuration and connections"""
    print("Testing AgentArx Configuration...")
    print("=" * 40)
    
    # Test settings validation
    try:
        settings.validate()
        print("✅ OpenAI API key configured")
        print(f"✅ Target configuration loaded: {settings.target_config.name}")
        print(f"  - URL: {settings.target_config.url}")
        print(f"  - Host: {settings.target_config.host}")
        print(f"  - Port: {settings.target_config.port}")
    except ValueError as e:
        print(f"❌ {e}")
        return False
    
    # Test LLM provider
    from .llm_gateway.openai_provider import OpenAIProvider
    provider = OpenAIProvider()
    
    if provider.is_available():
        print("✅ OpenAI provider available")
        
        # Test a simple chat
        try:
            response = provider.chat([{"role": "user", "content": "Hello, respond with 'OK'"}])
            if "OK" in response:
                print("✅ OpenAI API connection working")
            else:
                print("⚠️ OpenAI API responding but unexpected response")
        except Exception as e:
            print(f"❌ OpenAI API error: {e}")
            return False
    else:
        print("❌ OpenAI provider not available")
        return False
    
    # Test Reporter if configured
    from .integrations.reporting import DefectDojoReporter
    dd_reporter = DefectDojoReporter()
    
    if dd_reporter.is_configured():
        if dd_reporter.test_connection():
            print("✅ DefectDojo connection working")
        else:
            print("⚠️ DefectDojo configured but connection failed")
    else:
        print("⚠️ DefectDojo not configured (optional)")
    
    # Test target system configuration
    if settings.target_config:
        print(f"✅ Target system configured: {settings.target_config.url}")
    else:
        print("⚠️ Target system not configured")
    
    print("\nConfiguration test completed!")
    return True


def main():
    """Main entry point"""
    parser = setup_arguments()
    args = parser.parse_args()
    
    print("AgentArx - Automated Security Testing Framework")
    print("=" * 50)
    
    # Test configuration if requested
    if args.test_config:
        success = test_configuration()
        sys.exit(0 if success else 1)
    
    # Validate settings
    try:
        settings.validate()
    except ValueError as e:
        print(f"Configuration error: {e}")
        print("Set the OPENAI_API_KEY environment variable and try again.")
        sys.exit(1)
    
    # Initialize orchestrator
    orchestrator = AgentArxOrchestrator()
    
    # Validate attack JSON file exists
    attack_file = Path(args.file)
    if not attack_file.exists():
        print(f"Error: Attack definition not found: {args.file}")
        sys.exit(1)
    
    if not attack_file.suffix == '.json':
        print(f"Error: File must be a JSON file: {args.file}")
        sys.exit(1)
    
    try:
        # Run cooperative assessment
        results = orchestrator.execute_assessment(
            attack_json_path=str(attack_file),
            export_findings=args.export_findings,
            start_from=args.start_from
        )
        
        # Display summary
        print("\n" + "=" * 60)
        print("ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"Session ID: {results['session_id']}")
        print(f"Attack: {results['attack_name']}")
        print(f"Target: {results['target_url']}")
        print(f"Iterations: {results['iterations']}")
        
        report = results['report']
        print(f"\nVulnerabilities: {len(report.get('vulnerabilities', []))}")
        print(f"Successful Exploits: {len(results['attack_data'].get('successful_attacks', []))}")
        
        if args.export_findings:
            export_status = "✅ Success" if report.get('findings_exported', False) else "❌ Failed"
            print(f"Findings Export: {export_status}")
        
        print("\n" + "=" * 60)
        print("✅ Assessment completed successfully!")
        print("=" * 60)
        sys.exit(0)
            
    except KeyboardInterrupt:
        print("\nAssessment interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"Assessment failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()