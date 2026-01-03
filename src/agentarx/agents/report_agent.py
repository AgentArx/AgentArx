"""Report agent for generating comprehensive security reports"""

import json
import re
from typing import Dict, Any, List
from datetime import datetime
from ..llm_gateway.base import BaseLLMProvider
from ..scenario_parser.attack_scenario_schemas import AttackDefinition
from ..agent_msg_schemas import ReconData, AnalysisData, AttackData
from ..config.prompts import prompt_loader
from ..integrations.reporting import ReporterFactory


class ReportAgent:
    """
    Agent specialized in generating comprehensive security reports
    
    Responsibilities:
    - Synthesize data from all phases (recon, analysis, attack)
    - Generate executive summary with LLM
    - Provide remediation recommendations
    - Submit to configured reporter (DefectDojo, local file, etc.)
    """
    
    def __init__(self, llm_provider: BaseLLMProvider, reporter=None):
        self.llm_provider = llm_provider
        self.reporter = reporter or ReporterFactory.create()
    
    def generate_comprehensive_report(self,
                                     attack_def: AttackDefinition,
                                     recon_data: ReconData,
                                     analysis_data: AnalysisData,
                                     attack_data: AttackData) -> Dict[str, Any]:
        """
        Generate comprehensive security report from all assessment phases
        
        Args:
            attack_def: Attack definition that was executed
            recon_data: Intelligence gathered
            analysis_data: Vulnerabilities and analysis
            attack_data: Attack results and evidence
            
        Returns:
            Dict containing comprehensive report
        """
        print(f"📊 Generating comprehensive report...")
        print(f"   Attack: {attack_def.name}")
        print(f"   Vulnerabilities: {len(analysis_data.vulnerabilities)}")
        print(f"   Successful Exploits: {len(attack_data.successful_attacks)}\n")
        
        # Build base report structure with raw data
        base_report = self._build_base_report(
            attack_def, recon_data, analysis_data, attack_data
        )
        
        # Use LLM to synthesize and enhance report
        synthesized_report = self._synthesize_with_llm(
            attack_def, recon_data, analysis_data, attack_data
        )
        
        # Merge synthesized content with raw data
        comprehensive_report = {
            **base_report,
            'synthesized': synthesized_report,
            'generated_at': datetime.now().isoformat()
        }
        
        # Submit to configured reporter
        print(f"📤 Submitting report to {self.reporter.get_name()}...")
        if self.reporter.is_configured():
            self.reporter.submit_report(comprehensive_report)
        else:
            print(f"⚠️  Reporter not configured, skipping submission")
        
        print(f"✅ Report generation complete\n")
        
        # Print summary of findings
        self._print_findings_summary(analysis_data, attack_data)
        
        return comprehensive_report
    
    def _build_base_report(self,
                          attack_def: AttackDefinition,
                          recon_data: ReconData,
                          analysis_data: AnalysisData,
                          attack_data: AttackData) -> Dict[str, Any]:
        """Build base report structure with raw data"""
        
        return {
            'report_id': f"agentarx_{attack_def.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'attack_name': attack_def.name,
            'attack_goal': attack_def.name,
            'target_url': recon_data.target_url,
            
            # Raw data from each phase
            'reconnaissance': {
                'services_discovered': recon_data.discovered_services,
                'open_ports': recon_data.open_ports,
                'endpoints': recon_data.endpoints,
                'tech_stack': recon_data.tech_stack,
                'system_capabilities': recon_data.system_capabilities,
                'notes': recon_data.notes
            },
            'analysis': {
                'vulnerabilities': analysis_data.vulnerabilities,
                'attack_plan': analysis_data.attack_plan,
                'confidence_scores': analysis_data.confidence_scores,
                'risk_assessment': analysis_data.risk_assessment,
                'reasoning': analysis_data.reasoning,
                'notes': analysis_data.notes
            },
            'attack': {
                'attacks_attempted': attack_data.attacks_attempted,
                'successful_attacks': attack_data.successful_attacks,
                'failed_attacks': attack_data.failed_attacks,
                'vulnerabilities_confirmed': attack_data.vulnerabilities_confirmed,
                'evidence': attack_data.evidence,
                'notes': attack_data.notes
            },
            
            # Summary statistics
            'summary_stats': {
                'services_count': len(recon_data.discovered_services),
                'endpoints_count': len(recon_data.endpoints),
                'vulnerabilities_identified': len(analysis_data.vulnerabilities),
                'attacks_attempted': len(attack_data.attacks_attempted),
                'successful_exploits': len(attack_data.successful_attacks),
                'confirmed_vulnerabilities': len(attack_data.vulnerabilities_confirmed)
            }
        }
    
    def _synthesize_with_llm(self,
                            attack_def: AttackDefinition,
                            recon_data: ReconData,
                            analysis_data: AnalysisData,
                            attack_data: AttackData) -> Dict[str, Any]:
        """Use LLM to synthesize comprehensive report"""
        
        # Build context for LLM
        vulnerabilities_detail = self._format_vulnerabilities(analysis_data.vulnerabilities)
        evidence_summary = self._format_evidence(attack_data.evidence, attack_data.successful_attacks)
        
        # Load prompt template
        prompt_template = prompt_loader.get_template('report', 'report_synthesis')
        synthesis_prompt = prompt_template.format(
            attack_name=attack_def.name,
            attack_goal=attack_def.name,
            target_url=recon_data.target_url,
            assessment_date=datetime.now().strftime('%Y-%m-%d'),
            services_count=len(recon_data.discovered_services),
            endpoints_count=len(recon_data.endpoints),
            tech_stack=', '.join(recon_data.tech_stack[:10]) if recon_data.tech_stack else 'Not identified',
            recon_summary=recon_data.notes or 'Reconnaissance completed',
            vulnerabilities_detail=vulnerabilities_detail,
            attacks_attempted=len(attack_data.attacks_attempted),
            successful_attacks=len(attack_data.successful_attacks),
            failed_attacks=len(attack_data.failed_attacks),
            confirmed_vulns=len(attack_data.vulnerabilities_confirmed),
            evidence_summary=evidence_summary
        )
        
        print(f"   🤖 Synthesizing report with LLM...")
        
        # Get LLM synthesis (chat() returns string content directly)
        content = self.llm_provider.chat(
            messages=[{"role": "user", "content": synthesis_prompt}],
            response_format={"type": "json_object"}
        )
        
        # Extract JSON from response
        synthesized_data = self._extract_json_from_response(content)
        
        return synthesized_data
    
    def _format_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerabilities for prompt"""
        if not vulnerabilities:
            return "No vulnerabilities identified"
        
        lines = []
        for i, vuln in enumerate(vulnerabilities[:10], 1):
            severity = vuln.get('severity', 'unknown').upper()
            title = vuln.get('title', 'Unknown')
            description = vuln.get('description', 'No description')
            lines.append(f"{i}. [{severity}] {title}\n   {description}")
        
        if len(vulnerabilities) > 10:
            lines.append(f"\n... and {len(vulnerabilities) - 10} more vulnerabilities")
        
        return '\n'.join(lines)
    
    def _format_evidence(self, evidence: List[str], successful_attacks: List[Dict[str, Any]]) -> str:
        """Format evidence for prompt"""
        lines = []
        
        if evidence:
            lines.append("Evidence collected:")
            for item in evidence[:5]:
                lines.append(f"  - {item}")
        
        if successful_attacks:
            lines.append("\nSuccessful exploits:")
            for attack in successful_attacks[:5]:
                technique = attack.get('technique', 'Unknown')
                impact = attack.get('impact', 'Unknown impact')
                lines.append(f"  - {technique}: {impact}")
        
        return '\n'.join(lines) if lines else "No evidence or successful exploits"
    
    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from LLM response (handles markdown code blocks)"""
        if not response:
            return {}
        
        # Try to find JSON in markdown code blocks
        json_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try to parse entire response as JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON object anywhere in text
        json_match = re.search(r'\{[^{}]*"executive_summary".*?\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        
        # Return minimal structure if parsing fails
        return {
            'executive_summary': {
                'overall_risk': 'unknown',
                'summary': response[:500] if response else 'Report synthesis failed',
                'key_findings': [],
                'immediate_actions': []
            },
            'technical_findings': [],
            'remediation_plan': {'immediate': [], 'short_term': [], 'long_term': []},
            'attack_surface': {},
            'conclusion': 'Report synthesis completed with partial data'
        }
    
    def _print_findings_summary(self, analysis_data, attack_data):
        """Print a concise summary of key findings to the log"""
        print(f"\n{'='*60}")
        print("📋 SUMMARY OF FINDINGS")
        print(f"{'='*60}\n")
        
        # Vulnerabilities discovered
        if analysis_data.vulnerabilities:
            print(f"🔍 Vulnerabilities Identified ({len(analysis_data.vulnerabilities)}):")
            for i, vuln in enumerate(analysis_data.vulnerabilities[:5], 1):
                severity = vuln.get('severity', 'Unknown').upper()
                title = vuln.get('title', 'Unnamed vulnerability')
                print(f"  {i}. [{severity}] {title}")
            if len(analysis_data.vulnerabilities) > 5:
                print(f"  ... and {len(analysis_data.vulnerabilities) - 5} more")
            print()
        else:
            print("🔍 No vulnerabilities identified\n")
        
        # Successful attacks
        if attack_data.successful_attacks:
            print(f"✅ Successful Exploits ({len(attack_data.successful_attacks)}):")
            for i, attack in enumerate(attack_data.successful_attacks[:3], 1):
                attack_name = attack.get('name', 'Unnamed attack')
                print(f"  {i}. {attack_name}")
            if len(attack_data.successful_attacks) > 3:
                print(f"  ... and {len(attack_data.successful_attacks) - 3} more")
            print()
        else:
            print("✅ No successful exploits\n")
        
        # Confirmed vulnerabilities
        if attack_data.vulnerabilities_confirmed:
            print(f"🎯 Vulnerabilities Confirmed ({len(attack_data.vulnerabilities_confirmed)}):")
            for i, vuln in enumerate(attack_data.vulnerabilities_confirmed[:5], 1):
                vuln_id = vuln.get('id', 'unknown')
                print(f"  {i}. {vuln_id}")
            if len(attack_data.vulnerabilities_confirmed) > 5:
                print(f"  ... and {len(attack_data.vulnerabilities_confirmed) - 5} more")
            print()
        
        print(f"{'='*60}\n")
