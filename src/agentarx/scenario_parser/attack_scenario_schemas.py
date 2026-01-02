"""Pydantic schemas for attack scenario validation"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class Step(BaseModel):
    """Individual step in an attack or reconnaissance sequence"""
    name: str = Field(..., description="Name of the step")
    description: Optional[str] = Field(None, description="Step description")
    tool: str = Field(..., description="Tool to use (bash, python)")
    command: str = Field(..., description="Command or code to execute")
    expected_output: Optional[str] = Field(None, description="Expected output pattern")
    timeout: Optional[int] = Field(30, description="Timeout in seconds")


class AttackDefinition(BaseModel):
    """Attack or reconnaissance definition from JSON"""
    id: str = Field(..., description="Unique identifier")
    name: str = Field(..., description="Attack name")
    description: Optional[str] = Field(None, description="Attack description")
    category: str = Field(..., description="Attack category (recon, attack, etc.)")
    severity: Optional[str] = Field(None, description="Severity level")
    steps: List[Step] = Field(..., description="List of execution steps")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


class ParsedJson(BaseModel):
    """Container for parsed JSON content"""
    file_path: str = Field(..., description="Source file path")
    attack_definition: AttackDefinition = Field(..., description="Parsed attack definition")
    raw_content: Dict[str, Any] = Field(..., description="Raw JSON content")