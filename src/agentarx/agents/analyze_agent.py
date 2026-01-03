"""Analysis agent for identifying vulnerabilities and planning attacks"""

import json
import re
from typing import Dict, Any, List
from ..llm_gateway.base import BaseLLMProvider
from ..scenario_parser.attack_scenario_schemas import AttackDefinition
from ..config.prompts import prompt_loader
from ..agent_msg_schemas import ReconData, AnalysisData


class AnalyzeAgent:
    """
    Analyzes reconnaissance data to identify vulnerabilities and plan attacks
    
    Responsibilities:
    - Analyze recon data to identify potential vulnerabilities
    - Cross-reference with attack definition goals
    - Create detailed attack plan with steps
    - Determine if more reconnaissance is needed
    - Assess confidence and risk levels
    """
    
    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm_provider = llm_provider
    
    def analyze_and_plan(self, 
                        attack_def: AttackDefinition,
                        recon_data: ReconData) -> AnalysisData:
        """
        Analyze recon data and create attack plan using Chain of Thought reasoning
        
        Args:
            attack_def: Attack definition with goals
            recon_data: Intelligence from reconnaissance
            
        Returns:
            AnalysisData with vulnerabilities and attack plan
        """
        print(f"🧠 Analyzing reconnaissance data...")
        print(f"   Goal: {attack_def.name}")
        print(f"   Recon: {len(recon_data.discovered_services)} services, {len(recon_data.endpoints)} endpoints\n")
        
        # Step 1: Chain of Thought reasoning
        reasoning = self._perform_cot_analysis(attack_def, recon_data)
        
        # Step 2: Extract structured data with handoff logic
        analysis_data = self._extract_structured_analysis(reasoning, recon_data)
        
        # Display results
        if analysis_data.skip_to_report:
            print(f"⚠️  No exploitable vulnerabilities identified")
        elif analysis_data.needs_more_recon:
            print(f"🔄 Additional reconnaissance needed: {len(analysis_data.recon_requests)} requests")
        else:
            print(f"✅ Analysis complete: {len(analysis_data.vulnerabilities)} vulnerabilities identified")
            print(f"   Attack plan: {len(analysis_data.attack_plan)} steps\n")
        
        return analysis_data
    
    def _perform_cot_analysis(self, attack_def: AttackDefinition, recon_data: ReconData) -> str:
        """
        Perform Chain of Thought reasoning for vulnerability analysis
        
        Args:
            attack_def: Attack definition
            recon_data: Reconnaissance data
            
        Returns:
            Reasoning text from LLM
        """
        prompt_template = prompt_loader.get_template('analyze', 'cot_reasoning')
        reasoning_prompt = prompt_template.format(
            target_url=recon_data.target_url,
            services_count=len(recon_data.discovered_services),
            endpoints_count=len(recon_data.endpoints),
            tech_stack=', '.join(recon_data.tech_stack) if recon_data.tech_stack else 'Not identified',
            recon_data=self._format_recon_data(recon_data),
            attack_goal=attack_def.name,
            attack_context=self._format_attack_context(attack_def)
        )

        response = self.llm_provider.chat([{
            "role": "system",
            "content": reasoning_prompt
        }])
        
        return response
    
    def _extract_structured_analysis(self, reasoning: str, recon_data: ReconData) -> AnalysisData:
        """
        Extract structured analysis from reasoning with handoff logic
        
        Args:
            reasoning: Chain of thought reasoning from LLM
            recon_data: Original recon data for context
            
        Returns:
            AnalysisData with structured findings and handoff decisions
        """
        prompt_template = prompt_loader.get_template('analyze', 'structured_extraction')
        extraction_prompt = prompt_template.format(reasoning=reasoning)

        response = self.llm_provider.chat(
            messages=[{
                "role": "system",
                "content": extraction_prompt
            }],
            response_format={"type": "json_object"}
        )
        
        # Parse JSON and create AnalysisData
        return self._parse_analysis_results(response, reasoning)
    
    def _format_recon_data(self, recon_data: ReconData) -> str:
        """Format recon data for prompt"""
        sections = []
        
        if recon_data.discovered_services:
            services = "\n".join([
                f"  - {s.get('name', 'unknown')}: {s.get('version', 'unknown')} (port {s.get('port', 'unknown')})"
                if isinstance(s, dict) else f"  - {s}"
                for s in recon_data.discovered_services[:10]
            ])
            sections.append(f"Services:\n{services}")
        
        if recon_data.endpoints:
            endpoints = "\n".join([f"  - {ep}" for ep in recon_data.endpoints[:20]])
            sections.append(f"Endpoints:\n{endpoints}")
        
        if recon_data.tech_stack:
            tech = ", ".join(recon_data.tech_stack)
            sections.append(f"Technology Stack: {tech}")
        
        if recon_data.system_capabilities:
            caps = ", ".join(recon_data.system_capabilities)
            sections.append(f"Capabilities: {caps}")
        
        return "\n\n".join(sections) if sections else "Limited reconnaissance data available."
    
    def _format_attack_context(self, attack_def: AttackDefinition) -> str:
        """Format attack context from definition"""
        context = [f"Category: {attack_def.category}"]
        
        if attack_def.description:
            context.append(f"Description: {attack_def.description}")
        
        if attack_def.steps:
            steps = "\n".join([f"  {i+1}. {step.description}" 
                              for i, step in enumerate(attack_def.steps[:3])])
            context.append(f"Example Steps:\n{steps}")
        
        return "\n".join(context)
    
    def _parse_analysis_results(self, response: str, reasoning: str) -> AnalysisData:
        """Parse LLM response into AnalysisData structure"""
        data = self._extract_json_from_response(response)
        
        analysis = AnalysisData()
        
        # Core analysis data
        analysis.vulnerabilities = data.get('vulnerabilities', [])
        analysis.attack_plan = data.get('attack_plan', [])
        analysis.confidence_scores = data.get('confidence_scores', {})
        analysis.risk_assessment = data.get('risk_assessment', {})
        
        # Handoff flags
        analysis.needs_more_recon = data.get('needs_more_recon', False)
        analysis.recon_requests = data.get('recon_requests', [])
        analysis.skip_to_report = data.get('skip_to_report', False)
        analysis.analysis_complete = data.get('analysis_complete', False)
        
        # Metadata
        analysis.reasoning = reasoning  # Store full CoT reasoning
        analysis.notes = data.get('summary', '')
        
        # Validate handoff logic
        if analysis.needs_more_recon and not analysis.recon_requests:
            analysis.recon_requests = ["Additional service enumeration and version detection needed"]
        
        return analysis
    
    def _extract_json_from_response(self, content: str) -> Dict[str, Any]:
        """Extract JSON from LLM response (handles markdown code blocks)"""
        try:
            # Try direct parse
            return json.loads(content)
        except json.JSONDecodeError:
            # Try to find JSON in markdown code blocks
            json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            # Last resort: try to find any JSON object
            json_match = re.search(r'{.*}', content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(0))
            
            # Return minimal structure
            return {
                "analysis_complete": False,
                "error": "Could not parse JSON from LLM response",
                "raw_content": content,
                "skip_to_report": True,
                "next_agent_to_call": "report"
            }

