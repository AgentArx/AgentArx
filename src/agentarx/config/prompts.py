"""Prompt loader for agent prompts from YAML files"""

import yaml
from pathlib import Path
from typing import Dict, Any


class PromptLoader:
    """Loads agent prompts from config/prompts/ directory"""
    
    def __init__(self):
        # Get path to prompts directory (in config/)
        self.prompts_dir = Path(__file__).parent / "prompts"
    
    def load_prompt(self, agent_name: str) -> Dict[str, Any]:
        """
        Load prompt configuration for an agent
        
        Args:
            agent_name: Name of agent (e.g., 'recon', 'analyze', 'attack', 'report')
            
        Returns:
            Dictionary with prompt configuration
        """
        prompt_file = self.prompts_dir / f"{agent_name}_agent.yaml"
        
        if not prompt_file.exists():
            raise FileNotFoundError(f"Prompt file not found: {prompt_file}")
        
        with open(prompt_file, 'r') as f:
            return yaml.safe_load(f)
    
    def get_system_prompt(self, agent_name: str) -> str:
        """Get system prompt for an agent"""
        prompts = self.load_prompt(agent_name)
        return prompts.get('system_prompt', '')
    
    def get_template(self, agent_name: str, template_name: str) -> str:
        """Get a specific prompt template from agent config"""
        prompts = self.load_prompt(agent_name)
        templates = prompts.get('prompt_templates', {})
        return templates.get(template_name, '')


# Global instance
prompt_loader = PromptLoader()
