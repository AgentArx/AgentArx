"""Parser for attack scenario definitions (JSON format)"""

import json
from pathlib import Path
from typing import Dict, Any, List
from .attack_scenario_schemas import AttackDefinition, Step, ParsedJson


class AttackScenarioParser:
    """Parser for attack scenario JSON files"""
    
    def __init__(self):
        pass
    
    def parse_file(self, file_path: str) -> ParsedJson:
        """
        Parse a JSON file containing attack definitions
        
        Args:
            file_path: Path to the JSON file
            
        Returns:
            ParsedJson object with structured data
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"JSON file not found: {file_path}")
        
        if not path.suffix.lower() == '.json':
            raise ValueError(f"Only JSON files are supported. Got: {path.suffix}")
        
        with open(path, 'r', encoding='utf-8') as f:
            raw_content = json.load(f)
        
        # Convert raw JSON to our structured format
        attack_definition = self._convert_json_to_attack_definition(raw_content)
        
        return ParsedJson(
            file_path=str(path.absolute()),
            attack_definition=attack_definition,
            raw_content=raw_content
        )
    
    def _convert_json_to_attack_definition(self, raw_data: Dict[str, Any]) -> AttackDefinition:
        """Convert JSON format to AttackDefinition model"""
        from ..config.settings import settings
        
        steps = []
        
        # Extract steps from JSON format
        step_data = raw_data.get('steps', [])
        constraints = raw_data.get('constraints', {})
        timeout = constraints.get('timeout_seconds', 30)
        
        # Get system_prompt and substitute placeholder
        system_prompt = raw_data.get('system_prompt', '')
        if system_prompt == 'SYSTEM_PROMPT':
            system_prompt = settings.system_prompt
        
        for i, step_raw in enumerate(step_data):
            if isinstance(step_raw, dict):
                # Use the first example command as the default command
                examples = step_raw.get('examples', [])
                command = examples[0] if examples else ''
                
                step = Step(
                    name=step_raw.get('name', f'Step {i+1}'),
                    description=step_raw.get('description', ''),
                    tool='bash',  # Default tool, can be overridden by execution logic
                    command=command,
                    expected_output=None,
                    timeout=timeout
                )
                steps.append(step)
        
        # Generate ID from goal if not present
        step_id = f"JSON-{hash(raw_data.get('goal', 'unknown')) % 10000:04d}"
        
        return AttackDefinition(
            id=step_id,
            name=raw_data.get('goal', 'Unnamed Task'),
            description=raw_data.get('goal', ''),
            category='json_format',  # Will be refined by execution logic
            severity='medium',
            steps=steps,
            metadata={
                'system_prompt': system_prompt,
                'constraints': constraints,
                'stopping_conditions': constraints.get('stopping_conditions', []),
                'response_format': constraints.get('response_format', {}),
                'examples': raw_data.get('examples', [])
            }
        )

    
    def parse_multiple_files(self, file_paths: List[str]) -> List[ParsedJson]:
        """Parse multiple JSON files"""
        results = []
        for file_path in file_paths:
            try:
                result = self.parse_file(file_path)
                results.append(result)
            except Exception as e:
                print(f"Error parsing {file_path}: {e}")
                continue
        return results