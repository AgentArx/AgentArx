"""Session management for tracking assessment state"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import fields


class SessionManager:
    """Manages assessment sessions - generates IDs and saves final results"""
    
    def __init__(self, base_path: str = "results", scenario_name: str = None):
        self.base_path = Path(base_path)
        self.scenario_name = scenario_name
        if scenario_name:
            self.scenario_path = self.base_path / scenario_name
            self.scenario_path.mkdir(parents=True, exist_ok=True)
        else:
            self.scenario_path = self.base_path
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def create_session(self, attack_scenario_filename: str) -> str:
        """
        Create a deterministic session ID based on the attack scenario filename.
        This ensures the same attack scenario file always uses the same session,
        regardless of target configuration.
        
        Args:
            attack_scenario_filename: Name of the attack scenario file (e.g., "MAS_2025_00001__Prompt_Inject_Data_Leakage.json")
            
        Returns:
            Deterministic session ID based on filename (without extension)
        """
        # Use filename without extension as session ID
        filename = Path(attack_scenario_filename).stem
        self.scenario_name = filename
        self.scenario_path = self.base_path / filename
        self.scenario_path.mkdir(parents=True, exist_ok=True)
        session_id = f"session_{filename}"
        return session_id
    
    def save_assessment(self, session_id: str, assessment_data: Dict[str, Any]) -> Path:
        """
        Save complete assessment results to disk as report.json
        
        Args:
            session_id: Session identifier
            assessment_data: Complete assessment results (all phases + metadata)
            
        Returns:
            Path to saved results file
        """
        # Wrap with metadata
        wrapped_data = {
            'phase': 'report',
            'session_id': session_id,
            'target_url': assessment_data.get('target_url'),
            'attack_name': assessment_data.get('attack_name'),
            'attack_id': assessment_data.get('attack_id'),
            'timestamp': datetime.now().isoformat(),
            'data': assessment_data
        }
        
        # Save to fixed filename
        result_file = self.scenario_path / "report.json"
        with open(result_file, 'w') as f:
            json.dump(wrapped_data, f, indent=2)
        
        print(f"💾 Saved complete assessment to: {result_file}")
        return result_file
    
    def save_phase_result(self, 
                         session_id: str, 
                         phase_name: str, 
                         phase_data: Dict[str, Any],
                         target_url: str = None,
                         attack_name: str = None,
                         attack_id: str = None) -> Path:
        """
        Save individual phase results to disk with fixed filename (recon.json, analysis.json, attack.json)
        Session ID is deterministic based on attack_id + target_url.
        
        Args:
            session_id: Deterministic session identifier
            phase_name: Name of phase (recon, analysis, attack)
            phase_data: Phase-specific data
            target_url: Target URL for validation
            attack_name: Attack name for validation
            attack_id: Attack ID for validation
            
        Returns:
            Path to saved phase file
        """
        # Wrap data with metadata including run timestamp
        wrapped_data = {
            'phase': phase_name,
            'session_id': session_id,
            'target_url': target_url,
            'attack_name': attack_name,
            'attack_id': attack_id,
            'timestamp': datetime.now().isoformat(),
            'data': phase_data
        }
        
        # Save to fixed filename
        phase_file = self.scenario_path / f"{phase_name}.json"
        with open(phase_file, 'w') as f:
            json.dump(wrapped_data, f, indent=2)
        
        print(f"💾 Saved {phase_name} results to: {phase_file}")
        return phase_file
    
    def load_phase_result(self, 
                         phase_name: str,
                         expected_session_id: str,
                         expected_target_url: str = None) -> Optional[Dict[str, Any]]:
        """
        Load previously saved phase results from fixed filename.
        Validates session ID to ensure consistency.
        
        Args:
            phase_name: Name of phase (recon, analysis, attack)
            expected_session_id: Expected session ID (deterministic)
            expected_target_url: Expected target URL for validation (optional)
            
        Returns:
            Phase data dict (unwrapped) or None if not found
            
        Raises:
            ValueError: If session or metadata validation fails
        """
        phase_file = self.scenario_path / f"{phase_name}.json"
        if not phase_file.exists():
            return None
        
        with open(phase_file, 'r') as f:
            wrapped_data = json.load(f)
        
        # Validate session ID (strict - must match)
        if wrapped_data.get('session_id') != expected_session_id:
            raise ValueError(
                f"Session ID mismatch in {phase_name}.json: "
                f"expected '{expected_session_id}', found '{wrapped_data.get('session_id')}'. "
                "This indicates the file is from a different attack scenario or target."
            )
        
        # Validate target URL if provided (additional safety check)
        if expected_target_url and wrapped_data.get('target_url') != expected_target_url:
            raise ValueError(
                f"Target URL mismatch in {phase_name}.json: "
                f"expected '{expected_target_url}', found '{wrapped_data.get('target_url')}'"
            )
        
        print(f"📂 Loaded {phase_name} results from: {phase_file}")
        print(f"   Session: {wrapped_data.get('session_id')}")
        print(f"   Saved: {wrapped_data.get('timestamp')}")
        
        # Return unwrapped data
        return wrapped_data.get('data', {})
    
    @staticmethod
    def reconstruct_dataclass(dataclass_type, data: Dict[str, Any]):
        """
        Reconstruct a dataclass from a dictionary
        
        Args:
            dataclass_type: The dataclass type to reconstruct
            data: Dictionary with data
            
        Returns:
            Instance of dataclass_type
        """
        if data is None:
            return None
        
        # Get field names for the dataclass
        field_names = {f.name for f in fields(dataclass_type)}
        
        # Filter data to only include valid fields
        filtered_data = {k: v for k, v in data.items() if k in field_names}
        
        return dataclass_type(**filtered_data)
