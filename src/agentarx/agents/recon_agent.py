"""Reconnaissance agent - autonomously gathers intelligence about target"""

import json
from typing import List, Dict, Any
from ..llm_gateway.base import BaseLLMProvider
from ..mcp_client import get_mcp_client
from ..scenario_parser.attack_scenario_schemas import AttackDefinition
from ..config.settings import TargetConfig, settings
from ..config.prompts import prompt_loader
from ..agent_msg_schemas import ReconData


def _format_tool_preview(tool_name: str, tool_args: dict, max_length: int = 100) -> str:
    """Format tool arguments for concise logging preview"""
    if tool_name == 'execute_bash':
        cmd = tool_args.get('command', '')
        preview = cmd[:max_length] + ('...' if len(cmd) > max_length else '')
        return f"execute_bash: {preview}"
    elif tool_name == 'execute_python':
        code = tool_args.get('code', '')
        # Show first line or first N chars
        first_line = code.split('\n')[0]
        preview = first_line[:max_length] + ('...' if len(first_line) > max_length else '')
        return f"execute_python: {preview}"
    elif tool_name == 'crawl_url':
        url = tool_args.get('url', '')
        return f"crawl_url: {url}"
    else:
        # Generic: show first arg value
        if tool_args:
            first_val = str(list(tool_args.values())[0])[:max_length]
            return f"{tool_name}: {first_val}"
        return tool_name


class ReconAgent:
    """
    Autonomous reconnaissance agent that gathers intelligence about the target.
    
    Responsibilities:
    - Analyze attack goal to determine needed information
    - Gather target system information (ports, services, endpoints)
    - Identify tech stack and system capabilities
    - Provide intel to analysis agent
    """
    
    def __init__(self, llm_provider: BaseLLMProvider):
        self.llm_provider = llm_provider
        self.mcp_client = get_mcp_client()
    
    def gather_intelligence(self, 
                           attack_def: AttackDefinition,
                           target_config: TargetConfig) -> ReconData:
        """
        Gather intelligence about target system based on attack goals
        
        Args:
            attack_def: Attack definition with goals and context
            target_config: Target system configuration
            
        Returns:
            ReconData with discovered information
        """
        print(f"🔍 Analyzing attack goal: {attack_def.name}")
        print(f"🎯 Target: {target_config.url}\n")
        
        # Load prompt template
        prompt_template = prompt_loader.get_template('recon', 'initial_recon')
        system_prompt = prompt_template.format(
            target_url=target_config.url,
            target_host=target_config.host,
            target_port=target_config.port,
            attack_goal=attack_def.name,
            attack_hints=self._format_attack_steps(attack_def)
        )

        # Execute autonomous recon with tool calling
        recon_results = self._execute_autonomous_recon(
            system_prompt,
            max_calls=settings.max_recon_llm_calls
        )
        
        # Parse results into ReconData
        recon_data = self._parse_recon_results(
            recon_results,
            target_config
        )
        
        print(f"\n✅ Reconnaissance complete")
        print(f"   - Services discovered: {len(recon_data.discovered_services)}")
        if recon_data.discovered_services:
            for svc in recon_data.discovered_services[:3]:
                print(f"     • {svc.get('name', 'Unknown')}: {svc.get('description', 'N/A')}")
        print(f"   - Endpoints found: {len(recon_data.endpoints)}")
        if recon_data.endpoints:
            for ep in recon_data.endpoints[:5]:
                print(f"     • {ep}")
        print(f"   - Tech stack identified: {len(recon_data.tech_stack)}")
        if recon_data.tech_stack:
            print(f"     • {', '.join(recon_data.tech_stack)}")
        print(f"   - System capabilities: {len(recon_data.system_capabilities)}")
        if recon_data.system_capabilities:
            for cap in recon_data.system_capabilities[:3]:
                print(f"     • {cap}")
        print()
        
        return recon_data
    
    def gather_additional(self,
                         recon_requests: List[str],
                         existing_recon: ReconData,
                         target_config: TargetConfig) -> ReconData:
        """
        Gather additional intelligence based on requests from other agents
        
        Args:
            recon_requests: Specific information requests
            existing_recon: Previously gathered recon data
            target_config: Target system configuration
            
        Returns:
            Updated ReconData with additional information
        """
        print(f"🔍 Gathering additional intelligence:")
        for request in recon_requests:
            print(f"   - {request}")
        print()
        
        # Load prompt template
        prompt_template = prompt_loader.get_template('recon', 'additional_recon')
        system_prompt = prompt_template.format(
            target_url=target_config.url,
            services_count=len(existing_recon.discovered_services),
            endpoints_count=len(existing_recon.endpoints),
            tech_stack=', '.join(existing_recon.tech_stack) if existing_recon.tech_stack else 'None',
            recon_requests='\n'.join(f'- {req}' for req in recon_requests)
        )

        # Execute focused recon
        additional_results = self._execute_autonomous_recon(
            system_prompt,
            max_calls=10  # Fewer calls for targeted recon
        )
        
        # Merge with existing data
        updated_recon = self._merge_recon_data(
            existing_recon,
            additional_results
        )
        
        print(f"✅ Additional reconnaissance complete\n")
        
        return updated_recon
    
    def _execute_autonomous_recon(self, system_prompt: str, max_calls: int) -> Dict[str, Any]:
        """
        Execute autonomous recon using LLM with tool calling
        
        Args:
            system_prompt: Instructions for the LLM
            max_calls: Maximum number of LLM calls (safety limit)
            
        Returns:
            Parsed recon results from LLM
        """
        messages = [{"role": "system", "content": system_prompt}]
        tools = self.mcp_client.get_tools_for_llm()
        call_count = 0
        
        while call_count < max_calls:
            call_count += 1
            
            # Call LLM with tools
            response = self.llm_provider.chat_with_tools(messages, tools)
            
            # Check if LLM is done (no tool calls)
            if not response.get('tool_calls'):
                # LLM provided final response - request JSON mode for structured output
                messages.append({"role": "assistant", "content": response.get('content', '')})
                messages.append({"role": "user", "content": "Please provide the final reconnaissance results in valid JSON format only."})
                
                # Use JSON mode for guaranteed valid JSON
                final_response = self.llm_provider.chat_with_tools(
                    messages, 
                    tools=None,  # No tools for final response
                    response_format={"type": "json_object"}
                )
                content = final_response.get('content', '')
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
                
                print(f"   🔧 {_format_tool_preview(tool_name, tool_args)}")
                
                # Execute tool via MCP
                result = self.mcp_client.call_tool(tool_name, tool_args)
                
                # Add tool result to messages
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call['id'],
                    "name": tool_name,
                    "content": json.dumps(result)
                })
        
        # Max calls reached - force final extraction
        print(f"   ⚠️  Max LLM calls ({max_calls}) reached, forcing completion...")
        
        extraction_prompt = {
            "role": "user",
            "content": prompt_loader.get_template('recon', 'force_completion')
        }
        messages.append(extraction_prompt)
        
        final_response = self.llm_provider.chat_with_tools(messages, tools=None)
        return self._extract_json_from_response(final_response.get('content', '{}'))
    
    def _format_attack_steps(self, attack_def: AttackDefinition) -> str:
        """Format attack steps as hints for recon"""
        if not attack_def.steps:
            return "No specific hints provided."
        
        hints = []
        for i, step in enumerate(attack_def.steps[:3], 1):  # Show first 3 steps as hints
            hints.append(f"{i}. {step.description}")
        return "\n".join(hints)
    
    def _extract_json_from_response(self, content: str) -> Dict[str, Any]:
        """Extract JSON from LLM response with robust error handling"""
        import re
        
        # Try direct parse first
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            print(f"⚠️  Direct JSON parse failed: {e}")
        
        # Try to extract from markdown code blocks
        json_match = re.search(r'```(?:json)?\s*({.*?})\s*```', content, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError as e:
                print(f"⚠️  Markdown block JSON parse failed: {e}")
        
        # Try to find JSON object and sanitize
        json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', content, re.DOTALL)
        if json_match:
            json_str = json_match.group(0)
            # Attempt to fix common issues
            json_str = self._sanitize_json(json_str)
            try:
                return json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"⚠️  Sanitized JSON parse failed: {e}")
                print(f"Attempted JSON: {json_str[:200]}...")
        
        # Log the problematic response
        print(f"❌ Failed to extract valid JSON from LLM response")
        print(f"Response preview: {content[:300]}...")
        
        # Return minimal structure
        return {
            "recon_complete": False,
            "error": "Could not parse JSON from LLM response",
            "raw_content": content[:500]  # Limit size
        }
    
    def _sanitize_json(self, json_str: str) -> str:
        """Attempt to fix common JSON formatting issues"""
        import re
        # Replace single quotes with double quotes (but not in strings)
        # This is a simple heuristic - not perfect but handles common cases
        json_str = re.sub(r"(?<!\\)'([^']*?)(?<!\\)'", r'"\1"', json_str)
        # Remove trailing commas before closing braces/brackets
        json_str = re.sub(r',\s*([}\]])', r'\1', json_str)
        return json_str
    
    def _parse_recon_results(self, results: Dict[str, Any], target_config: TargetConfig) -> ReconData:
        """Parse LLM results into ReconData structure"""
        recon_data = ReconData(
            target_url=target_config.url,
            target_host=target_config.host,
            target_port=target_config.port
        )
        
        recon_data.discovered_services = results.get('discovered_services', [])
        recon_data.open_ports = results.get('open_ports', [])
        recon_data.endpoints = results.get('endpoints', [])
        recon_data.tech_stack = results.get('tech_stack', [])
        recon_data.system_capabilities = results.get('system_capabilities', [])
        recon_data.recon_complete = results.get('recon_complete', False)
        recon_data.notes = results.get('summary', '') or results.get('error', '')
        recon_data.raw_outputs = results
        
        return recon_data
    
    def _merge_recon_data(self, existing: ReconData, additional: Dict[str, Any]) -> ReconData:
        """Merge additional recon results with existing data"""
        # Add new services
        if 'new_services' in additional:
            existing.discovered_services.extend(additional['new_services'])
        
        # Add new endpoints
        if 'new_endpoints' in additional:
            existing.endpoints.extend(additional['new_endpoints'])
        
        # Update notes
        if 'additional_info' in additional:
            existing.notes += f" | {additional['additional_info']}"
        
        return existing

