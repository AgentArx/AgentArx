"""Data structures for passing information between cooperative agents"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class AgentRequest:
    """Request from one agent to go back to a previous phase"""
    request_type: str  # 'more_recon', 'reanalysis'
    reason: str
    specific_tasks: List[str] = field(default_factory=list)


@dataclass
class ReconData:
    """Data collected by reconnaissance agent"""
    # Target information
    target_url: str
    target_host: str
    target_port: int
    
    # Discovered information
    discovered_services: List[Dict[str, Any]] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    system_capabilities: List[str] = field(default_factory=list)
    
    # Raw outputs from recon tools
    raw_outputs: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    recon_complete: bool = False
    notes: str = ""


@dataclass
class AnalysisData:
    """Data from analysis agent"""
    # Identified vulnerabilities
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    
    # Attack plan
    attack_plan: List[Dict[str, str]] = field(default_factory=list)  # List of planned steps
    
    # Confidence and risk
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    risk_assessment: Dict[str, str] = field(default_factory=dict)
    
    # Feedback requests
    needs_more_recon: bool = False
    recon_requests: List[str] = field(default_factory=list)
    skip_to_report: bool = False  # No exploitable vulnerabilities found
    
    # Metadata
    analysis_complete: bool = False
    reasoning: str = ""  # Chain of thought reasoning from analysis
    notes: str = ""


@dataclass
class AttackData:
    """Data from attack agent"""
    # Attack execution results
    attacks_attempted: List[Dict[str, Any]] = field(default_factory=list)
    successful_attacks: List[Dict[str, Any]] = field(default_factory=list)
    failed_attacks: List[Dict[str, Any]] = field(default_factory=list)
    
    # Findings
    vulnerabilities_confirmed: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)  # Paths to evidence files
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Feedback requests
    needs_more_recon: bool = False
    needs_reanalysis: bool = False
    requests: List[AgentRequest] = field(default_factory=list)
    
    # Metadata
    attack_complete: bool = False
    notes: str = ""
