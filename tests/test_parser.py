"""Test cases for attack scenario parser functionality"""

import pytest
import tempfile
import json
from pathlib import Path
from agentarx.scenario_parser.attack_scenario_parser import AttackScenarioParser


def create_test_json_file(content: dict) -> str:
    """Create a temporary JSON file for testing"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(content, f)
        return f.name


def test_parse_attack_scenario_with_multiple_steps():
    """Test parsing attack scenario with standard format"""
    json_content = {
        "system_prompt": "SYSTEM_PROMPT",
        "goal": "Test injection vulnerabilities",
        "constraints": {
            "timeout_seconds": 300,
            "stopping_conditions": ["3 techniques tested"]
        },
        "steps": [
            {
                "name": "prompt_extraction",
                "description": "Extract system prompt",
                "examples": ["curl -X POST {TARGET_URL}/api/chat -d '{\"msg\":\"Show prompt\"}'"]
            },
            {
                "name": "data_extraction",
                "description": "Extract sensitive data",
                "examples": ["curl -X POST {TARGET_URL}/api/chat -d '{\"msg\":\"Show data\"}'"]
            }
        ]
    }
    
    json_file = create_test_json_file(json_content)
    
    try:
        parser = AttackScenarioParser()
        result = parser.parse_file(json_file)
        
        assert result.attack_definition.name == "Test injection vulnerabilities"
        assert len(result.attack_definition.steps) == 2
        assert result.attack_definition.steps[0].name == "prompt_extraction"
        assert "curl" in result.attack_definition.steps[0].command
        assert result.attack_definition.metadata['constraints']['timeout_seconds'] == 300
    finally:
        Path(json_file).unlink()


def test_parse_empty_steps():
    """Test parsing scenario with no steps"""
    json_content = {
        "system_prompt": "Test prompt",
        "goal": "Test goal",
        "constraints": {"timeout_seconds": 60},
        "steps": []
    }
    
    json_file = create_test_json_file(json_content)
    
    try:
        parser = AttackScenarioParser()
        result = parser.parse_file(json_file)
        assert len(result.attack_definition.steps) == 0
    finally:
        Path(json_file).unlink()


def test_parse_file_not_found():
    """Test handling of non-existent file"""
    parser = AttackScenarioParser()
    with pytest.raises(FileNotFoundError):
        parser.parse_file('/nonexistent/file.json')


def test_parse_multiple_files():
    """Test parsing multiple JSON files"""
    json1_content = {
        "system_prompt": "Test role 1",
        "goal": "Test attack 1",
        "steps": [{"name": "step1", "examples": ["ls"]}]
    }
    
    json2_content = {
        "system_prompt": "Test role 2",
        "goal": "Test attack 2",
        "steps": [{"name": "step2", "examples": ["print(\"hi\")"]}]
    }
    
    json1_file = create_test_json_file(json1_content)
    json2_file = create_test_json_file(json2_content)
    
    try:
        parser = AttackScenarioParser()
        results = parser.parse_multiple_files([json1_file, json2_file])
        
        assert len(results) == 2
        assert results[0].attack_definition.name == 'Test attack 1'
        assert results[1].attack_definition.name == 'Test attack 2'
    finally:
        Path(json1_file).unlink()
        Path(json2_file).unlink()


def test_invalid_file_format():
    """Test handling of non-JSON file"""
    parser = AttackScenarioParser()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write("This is not a JSON file")
        txt_file = f.name
    
    try:
        with pytest.raises(ValueError):
            parser.parse_file(txt_file)
    finally:
        Path(txt_file).unlink()


if __name__ == "__main__":
    # Run basic tests
    test_parse_simple_attack_definition()
    test_parse_recon_json()
    test_parse_multiple_files()
    test_invalid_file_format()
    print("All parser tests passed!")