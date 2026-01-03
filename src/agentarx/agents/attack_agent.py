"""Attack agent - autonomously executes attacks based on analysis"""

import json
import re
from typing import Dict, Any, List
from ..llm_gateway.base import BaseLLMProvider
from ..mcp_client import get_mcp_client
from ..scenario_parser.attack_scenario_schemas import AttackDefinition
from ..config.settings import settings
from ..config.prompts import prompt_loader
from ..agent_msg_schemas import ReconData, AnalysisData, AttackData, AgentRequest


def _format_tool_preview(tool_name: str, tool_args: dict, max_length: int = 100) -> str:
    """Format tool arguments for concise logging preview"""
    if tool_name == 'execute_bash':
        cmd = tool_args.get('command', '')
        preview = cmd[:max_length] + ('...' if len(cmd) > max_length else '')
        return f"execute_bash: {preview}"
    elif tool_name == 'execute_python':
        code = tool_args.get('code', '')
        first_line = code.split('\n')[0]
        preview = first_line[:max_length] + ('...' if len(first_line) > max_length else '')
        return f"execute_python: {preview}"
    elif tool_name == 'crawl_url':
        url = tool_args.get('url', '')
        return f"crawl_url: {url}"
    else:
        if tool_args:
            first_val = str(list(tool_args.values())[0])[:max_length]
            return f"{tool_name}: {first_val}"
        return tool_name


class AttackAgent:
    """
    Autonomous attack agent that executes exploits based on analysis
    
    Responsibilities:
    - Execute attack plan from analysis agent
    - Use tools (bash, python) to run attack commands
    - Adapt based on results (success/failure)
    - Determine if more recon or reanalysis needed
    - Collect evidence of successful exploits
    """
    
    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm_provider = llm_provider
        self.mcp_client = get_mcp_client()
    
    def execute_attack(self,
                      attack_def: AttackDefinition,
                      recon_data: ReconData,
                      analysis_data: AnalysisData) -> AttackData:
        """
        Execute attack based on analysis plan
        
        Args:
            attack_def: Attack definition with goals and hints
            recon_data: Intelligence from reconnaissance
            analysis_data: Attack plan from analysis
            
        Returns:
            AttackData with results and findings
        """
        print(f"⚔️  Executing attack: {attack_def.name}")
        print(f"   Goal: {attack_def.name}")
        print(f"   Vulnerabilities: {len(analysis_data.vulnerabilities)}")
        print(f"   Attack plan steps: {len(analysis_data.attack_plan)}\n")
        
        # Build attack prompt with context
        system_prompt = self._build_attack_prompt(
            attack_def, recon_data, analysis_data
        )
        
        # Execute autonomous attack with tool calling
        attack_results = self._execute_autonomous_attack(
            system_prompt,
            max_calls=settings.max_attack_llm_calls
        )
        
        # Parse results into AttackData
        attack_data = self._parse_attack_results(attack_results)
        
        print(f"✅ Attack execution complete")
        print(f"   - Attempts: {len(attack_data.attacks_attempted)}")
        print(f"   - Successful: {len(attack_data.successful_attacks)}")
        print(f"   - Failed: {len(attack_data.failed_attacks)}")
        print(f"   - Vulnerabilities confirmed: {len(attack_data.vulnerabilities_confirmed)}\n")
        
        return attack_data
    
    def _build_attack_prompt(self,
                            attack_def: AttackDefinition,
                            recon_data: ReconData,
                            analysis_data: AnalysisData) -> str:
        """Build system prompt for attack execution"""
        
        vulnerabilities_text = "\n".join([
            f"- [{v.get('severity', 'unknown').upper()}] {v.get('title', 'Unknown')}: {v.get('description', 'No description')}"
            for v in analysis_data.vulnerabilities[:5]
        ]) if analysis_data.vulnerabilities else "No specific vulnerabilities identified"
        
        attack_plan_text = "\n".join([
            f"{i}. {step.get('action', 'Unknown')} - {step.get('technique', 'No technique')}"
            for i, step in enumerate(analysis_data.attack_plan[:10], 1)
        ]) if analysis_data.attack_plan else "No specific plan provided"
        
        scenario_hints = ""
        if attack_def.steps:
            scenario_hints = "\n".join([
                f"- {step.name}: {step.command}"
                for step in attack_def.steps[:3]
            ])
        if not scenario_hints:
            scenario_hints = "No hints provided"
        
        # Handle services - may be dicts or other types
        service_names = []
        for s in recon_data.discovered_services[:5]:
            if isinstance(s, dict):
                service_names.append(s.get('name', 'unknown'))
            else:
                service_names.append(str(s))
        services = ', '.join(service_names) if service_names else "None identified"
        
        tech_stack = ', '.join(recon_data.tech_stack[:5]) if recon_data.tech_stack else "Not identified"
        # Ensure all endpoints are strings; if dict, use 'path' if present, else str(endpoint)
        endpoints_list = []
        if recon_data.endpoints:
            for ep in recon_data.endpoints[:10]:
                if isinstance(ep, str):
                    endpoints_list.append(ep)
                elif isinstance(ep, dict):
                    endpoints_list.append(ep.get('path', str(ep)))
                else:
                    endpoints_list.append(str(ep))
            endpoints = ', '.join(endpoints_list)
        else:
            endpoints = "None"
        
        # Load prompt template
        prompt_template = prompt_loader.get_template('attack', 'attack_execution')
        return prompt_template.format(
            target_url=recon_data.target_url,
            services=services,
            tech_stack=tech_stack,
            endpoints=endpoints,
            attack_goal=attack_def.name,
            vulnerabilities=vulnerabilities_text,
            attack_plan=attack_plan_text,
            scenario_hints=scenario_hints
        )
    
    def _execute_autonomous_attack(self, system_prompt: str, max_calls: int) -> Dict[str, Any]:
        """Execute autonomous attack with LLM tool calling loop"""
        
        messages = [{"role": "system", "content": system_prompt}]
        tools = self.mcp_client.get_tools_for_llm()
        
        print(f"🤖 Starting autonomous attack (max {max_calls} LLM calls)...")
        
        for call_num in range(1, max_calls + 1):
            print(f"   💭 LLM call {call_num}/{max_calls}...")
            
            # Truncate message history to prevent context overflow
            # Keep system prompt + remove oldest assistant/tool exchanges
            if len(messages) > 15:
                # Always keep system prompt at index 0
                system_msg = messages[0]
                # Remove messages from position 1 until we're under limit
                # Skip in chunks to avoid breaking tool call/response pairs
                messages_to_keep = [system_msg]
                i = len(messages) - 12  # Keep last ~12 messages
                while i < len(messages):
                    msg = messages[i]
                    # If this is a tool message, make sure we have its parent assistant message
                    if msg.get('role') == 'tool':
                        # Find the assistant message with tool_calls before this
                        for j in range(i-1, 0, -1):
                            if messages[j].get('role') == 'assistant' and messages[j].get('tool_calls'):
                                # Include from that assistant message onwards
                                messages_to_keep.extend(messages[j:])
                                break
                        break
                    i += 1
                else:
                    # No tool messages found, just keep last N
                    messages_to_keep.extend(messages[-12:])
                messages = messages_to_keep
            
            # Get LLM response with tool calling
            response = self.llm_provider.chat_with_tools(messages, tools)
            
            # Check if LLM is done (no tool calls)
            if not response.get('tool_calls'):
                # LLM provided final response
                content = response.get('content', '')
                return self._extract_json_from_response(content)
            
            # Add assistant message to history
            assistant_msg = {"role": "assistant", "content": response.get('content') or ""}
            if response.get('tool_calls'):
                assistant_msg['tool_calls'] = response['tool_calls']
            messages.append(assistant_msg)
            
            # Execute tool calls
            for tool_call in response['tool_calls']:
                tool_name = tool_call['function']['name']
                tool_args = json.loads(tool_call['function']['arguments'])
                
                print(f"      🔧 {_format_tool_preview(tool_name, tool_args)}")
                
                # Execute tool via MCP
                tool_result = self.mcp_client.call_tool(tool_name, tool_args)
                
                # Add tool result to conversation
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call['id'],
                    "name": tool_name,
                    "content": json.dumps(tool_result)
                })
        
        # Max calls reached - force final extraction
        print(f"   ⚠️  Max LLM calls ({max_calls}) reached, forcing completion...")
        
        extraction_prompt = {
            "role": "user",
            "content": prompt_loader.get_template('attack', 'force_completion')
        }
        
        messages.append(extraction_prompt)
        response = self.llm_provider.chat(
            messages=messages,
            response_format={"type": "json_object"}
        )
        final_content = response
        
        return self._extract_json_from_response(final_content) or {
            "attack_complete": True,
            "attacks_attempted": [],
            "successful_attacks": [],
            "failed_attacks": [],
            "vulnerabilities_confirmed": [],
            "evidence": [],
            "summary": "Max iterations reached with incomplete results"
        }
    
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
        
        # Try to parse the entire response as JSON
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Try to find JSON object anywhere in the text
        json_match = re.search(r'\{[^{}]*"attack_complete"[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass
        
        return {}
    
    def _parse_attack_results(self, results: Dict[str, Any]) -> AttackData:
        """Parse LLM results into AttackData structure"""
        
        attack_data = AttackData()
        
        attack_data.attacks_attempted = results.get('attacks_attempted', [])
        attack_data.successful_attacks = results.get('successful_attacks', [])
        attack_data.failed_attacks = results.get('failed_attacks', [])
        attack_data.vulnerabilities_confirmed = results.get('vulnerabilities_confirmed', [])
        attack_data.evidence = results.get('evidence', [])
        attack_data.new_findings = results.get('new_findings', [])
        
        # Determine if more work is needed
        attack_data.needs_more_recon = results.get('needs_more_recon', False)
        attack_data.needs_reanalysis = results.get('needs_reanalysis', False)
        
        attack_data.attack_complete = results.get('attack_complete', True)
        attack_data.notes = results.get('summary', 'Attack execution completed')
        
        return attack_data

