"""DefectDojo integration for vulnerability reporting"""

import json
import requests
from typing import Dict, Any, List, Optional
from ...config.settings import settings
from .base import BaseReporter


class DefectDojoReporter(BaseReporter):
    """Reporter for submitting findings to DefectDojo"""
    
    def __init__(self):
        # Use generic reporter settings
        self.token = settings.reporter_token or settings.reporter_api_key
        self.base_url = settings.reporter_url
        # Ensure base_url ends with /api/v2
        if self.base_url and not self.base_url.endswith('/api/v2'):
            self.base_url = self.base_url.rstrip('/') + '/api/v2'
        self.headers = {
            'Authorization': f'Token {self.token}' if self.token else '',
            'Content-Type': 'application/json'
        }
    
    def is_configured(self) -> bool:
        """Check if DefectDojo integration is properly configured"""
        return bool(self.base_url and self.token)
    
    def get_name(self) -> str:
        """Get reporter name"""
        return "DefectDojo"
    
    def submit_report(self, report: Dict[str, Any]) -> bool:
        """Submit report to DefectDojo (alias for submit_findings)"""
        return self.submit_findings(report)
    
    def submit_findings(self, report: Dict[str, Any]) -> bool:
        """
        Submit security findings to DefectDojo
        
        Args:
            report: Comprehensive security report
            
        Returns:
            Success status
        """
        if not self.is_configured():
            print("DefectDojo not configured. Set DEFECTDOJO_URL and DEFECTDOJO_TOKEN environment variables.")
            return False
        
        try:
            # Convert report to DefectDojo format
            defectdojo_findings = self._convert_to_defectdojo_format(report)
            
            # Submit findings
            success_count = 0
            for finding in defectdojo_findings:
                if self._submit_single_finding(finding):
                    success_count += 1
            
            print(f"Successfully submitted {success_count}/{len(defectdojo_findings)} findings to DefectDojo")
            return success_count == len(defectdojo_findings)
            
        except Exception as e:
            print(f"Error submitting to DefectDojo: {e}")
            return False
    
    def _convert_to_defectdojo_format(self, report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Convert AgentArx report to DefectDojo finding format"""
        findings = []
        
        # Extract data from report structure
        attack_name = report.get('attack_name', 'Unknown Attack')
        target_url = report.get('target_url', 'Unknown Target')
        
        # Get vulnerabilities from analysis phase
        analysis = report.get('analysis', {})
        vulnerabilities = analysis.get('vulnerabilities', [])
        
        # Get attack results
        attack = report.get('attack', {})
        successful_attacks = attack.get('successful_attacks', [])
        vulnerabilities_confirmed = attack.get('vulnerabilities_confirmed', [])
        attacks_attempted = attack.get('attacks_attempted', [])
        
        # Create findings from confirmed vulnerabilities
        for vuln_confirmed in vulnerabilities_confirmed:
            vuln_id = vuln_confirmed.get('id', 'Unknown')
            # Find matching vulnerability details from analysis
            vuln_details = next((v for v in vulnerabilities if v.get('id') == vuln_id), {})
            
            finding = {
                'title': f"{attack_name} - {vuln_details.get('title', vuln_id)}",
                'description': self._create_confirmed_finding_description(
                    attack_name, target_url, vuln_details, vuln_confirmed
                ),
                'severity': self._map_severity(vuln_details.get('severity', 'Medium')),
                'numerical_severity': self._map_numerical_severity(vuln_details.get('severity', 'Medium')),
                'test': settings.tracker_test_id or 1,
                'found_by': [settings.tracker_user_id],
                'product_name': settings.tracker_product_name,
                'engagement_name': settings.tracker_engagement_name,
                'product_type_name': settings.tracker_product_type_name,
                'active': True,
                'verified': True,
                'false_p': False,
                'duplicate': False,
                'static_finding': False,
                'dynamic_finding': True,
                'impact': vuln_details.get('impact', 'Security vulnerability confirmed through testing'),
                'steps_to_reproduce': self._create_reproduction_steps(vuln_confirmed, attacks_attempted),
                'mitigation': self._extract_mitigation(vuln_details),
                'references': 'AgentArx Automated Security Assessment'
            }
            findings.append(finding)
        
        # Create findings from successful attacks (if not already covered by confirmed vulns)
        confirmed_ids = {v.get('id') for v in vulnerabilities_confirmed}
        for attack_result in successful_attacks:
            technique = attack_result.get('technique', 'Unknown')
            if technique not in confirmed_ids:
                finding = {
                    'title': f"{attack_name} - {technique}",
                    'description': self._create_attack_finding_description(
                        attack_name, target_url, attack_result
                    ),
                    'severity': self._map_severity(attack_result.get('severity', 'Medium')),
                    'numerical_severity': self._map_numerical_severity(attack_result.get('severity', 'Medium')),
                    'test': settings.tracker_test_id or 1,
                    'found_by': [settings.tracker_user_id],
                    'product_name': settings.tracker_product_name,
                    'engagement_name': settings.tracker_engagement_name,
                    'product_type_name': settings.tracker_product_type_name,
                    'active': True,
                    'verified': True,
                    'false_p': False,
                    'duplicate': False,
                    'static_finding': False,
                    'dynamic_finding': True,
                    'impact': attack_result.get('impact', 'Security issue identified'),
                    'steps_to_reproduce': self._create_attack_reproduction_steps(attack_result),
                    'mitigation': 'Investigate and implement appropriate security controls.',
                    'references': 'AgentArx Automated Security Assessment'
                }
                findings.append(finding)
        
        # If no confirmed vulnerabilities or successful attacks, create info finding
        if not findings:
            finding = {
                'title': f"{attack_name} - Assessment Complete",
                'description': f"Automated security assessment completed for {target_url}.\n\n"
                              f"Attack: {attack_name}\n"
                              f"Vulnerabilities Identified: {len(vulnerabilities)}\n"
                              f"Attacks Attempted: {len(attacks_attempted)}\n"
                              f"Successful Exploits: {len(successful_attacks)}\n\n"
                              f"No critical vulnerabilities were confirmed during testing.",
                'severity': 'Info',
                'numerical_severity': 'S4',
                'test': settings.tracker_test_id or 1,
                'found_by': [settings.tracker_user_id],
                'product_name': settings.tracker_product_name,
                'engagement_name': settings.tracker_engagement_name,
                'product_type_name': settings.tracker_product_type_name,
                'active': True,
                'verified': False,
                'false_p': False,
                'duplicate': False,
                'static_finding': False,
                'dynamic_finding': True,
                'impact': 'Assessment completed with no confirmed exploitable vulnerabilities.',
                'steps_to_reproduce': 'Automated assessment executed via AgentArx framework.',
                'mitigation': 'Continue regular security assessments.',
                'references': 'AgentArx Automated Security Assessment'
            }
            findings.append(finding)
        
        return findings
    
    def _create_confirmed_finding_description(self, attack_name: str, target_url: str, 
                                              vuln_details: Dict[str, Any], 
                                              vuln_confirmed: Dict[str, Any]) -> str:
        """Create detailed finding description for confirmed vulnerability"""
        description = f"""AgentArx Security Assessment - Confirmed Vulnerability

Target: {target_url}
Attack: {attack_name}
Vulnerability ID: {vuln_details.get('id', 'Unknown')}

DESCRIPTION:
{vuln_details.get('description', 'No description available')}

EVIDENCE:
{vuln_confirmed.get('evidence', 'Vulnerability confirmed through exploitation')}

AFFECTED COMPONENT:
{vuln_details.get('affected_component', 'See target URL')}

CVSS SCORE: {vuln_details.get('cvss_score', 'N/A')}
EXPLOITABILITY: {vuln_details.get('exploitability', 'Unknown')}
"""
        return description.strip()
    
    def _create_attack_finding_description(self, attack_name: str, target_url: str,
                                           attack_result: Dict[str, Any]) -> str:
        """Create finding description from successful attack"""
        return f"""AgentArx Security Assessment - Successful Exploit

Target: {target_url}
Attack: {attack_name}
Technique: {attack_result.get('technique', 'Unknown')}

IMPACT:
{attack_result.get('impact', 'Security vulnerability successfully exploited')}

EVIDENCE:
{attack_result.get('evidence', 'No additional evidence provided')}
"""
    
    def _create_reproduction_steps(self, vuln_confirmed: Dict[str, Any], 
                                   attacks_attempted: List[Dict[str, Any]]) -> str:
        """Create steps to reproduce from attack data"""
        vuln_id = vuln_confirmed.get('id', 'Unknown')
        
        # Find matching attack attempts
        related_attacks = [a for a in attacks_attempted 
                          if vuln_id.lower() in str(a.get('technique', '')).lower()]
        
        steps = []
        for i, attack in enumerate(related_attacks[:3], 1):
            steps.append(f"{i}. {attack.get('technique', 'Unknown technique')}")
            if attack.get('command'):
                steps.append(f"   Command: {attack['command']}")
            if attack.get('target'):
                steps.append(f"   Target: {attack['target']}")
        
        if not steps:
            return f"Vulnerability {vuln_id} confirmed through automated testing."
        
        return "\n".join(steps)
    
    def _create_attack_reproduction_steps(self, attack_result: Dict[str, Any]) -> str:
        """Create reproduction steps from attack result"""
        return f"""Technique: {attack_result.get('technique', 'Unknown')}
Target: {attack_result.get('target', 'See description')}
Impact: {attack_result.get('impact', 'Security issue confirmed')}
"""
    
    def _extract_mitigation(self, vuln_details: Dict[str, Any]) -> str:
        """Extract or generate mitigation advice"""
        # Check if mitigation is in vulnerability details
        if 'mitigation' in vuln_details:
            return vuln_details['mitigation']
        if 'remediation' in vuln_details:
            return vuln_details['remediation']
        
        # Generate based on vulnerability type
        return 'Review vulnerability details and implement appropriate security controls. Conduct thorough testing after remediation.'
    
    def _map_severity(self, agentarx_severity: str) -> str:
        """Map AgentArx severity to DefectDojo severity"""
        severity_mapping = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'info': 'Info',
            'informational': 'Info'
        }
        return severity_mapping.get(agentarx_severity.lower(), 'Medium')
    
    def _map_numerical_severity(self, agentarx_severity: str) -> str:
        """Map AgentArx severity to DefectDojo numerical severity (S0-S4)"""
        numerical_mapping = {
            'critical': 'S0',
            'high': 'S1',
            'medium': 'S2',
            'low': 'S3',
            'info': 'S4',
            'informational': 'S4'
        }
        return numerical_mapping.get(agentarx_severity.lower(), 'S2')
    
    def _submit_single_finding(self, finding: Dict[str, Any]) -> bool:
        """Submit a single finding to DefectDojo"""
        try:
            url = f"{self.base_url}/findings/"
            response = requests.post(
                url,
                headers=self.headers,
                json=finding,
                timeout=settings.timeout_vulnerability_tracker,
                verify=False
            )
            
            if response.status_code in [200, 201]:
                print(f"Successfully submitted finding: {finding['title']}")
                return True
            else:
                print(f"Failed to submit finding: {finding['title']} (Status: {response.status_code})")
                print(f"Response: {response.text}")
                return False
                
        except Exception as e:
            print(f"Error submitting finding {finding['title']}: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test connection to DefectDojo"""
        if not self.is_configured():
            print("DefectDojo not configured")
            return False
        
        try:
            url = f"{self.base_url}/users/"
            response = requests.get(url, headers=self.headers, timeout=settings.timeout_vulnerability_tracker, verify=False)
            
            if response.status_code == 200:
                print("DefectDojo connection successful")
                return True
            else:
                print(f"DefectDojo connection failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"DefectDojo connection error: {e}")
            return False