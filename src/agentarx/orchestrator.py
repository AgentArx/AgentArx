"""Cooperative agent orchestrator - coordinates autonomous agents in sequence"""

from typing import Dict, Any, Optional
from pathlib import Path

from .llm_gateway.openai_provider import OpenAIProvider
from .scenario_parser.attack_scenario_parser import AttackScenarioParser
from .agents.recon_agent import ReconAgent
from .agents.analyze_agent import AnalyzeAgent
from .agents.attack_agent import AttackAgent
from .agents.report_agent import ReportAgent
from .integrations.reporting.factory import ReporterFactory
from .session_manager import SessionManager
from .log_manager import LogManager
from .config.settings import settings, TargetConfig
from .agent_msg_schemas import ReconData, AnalysisData, AttackData


class AgentArxOrchestrator:
    """Orchestrates cooperative agents: Recon → Analyze → Attack → Report"""
    
    def __init__(self):
        self.llm_provider = OpenAIProvider()
        self.json_parser = AttackScenarioParser()
        
        # Initialize cooperative agents
        self.recon_agent = ReconAgent(self.llm_provider)
        self.analyze_agent = AnalyzeAgent(self.llm_provider)
        self.attack_agent = AttackAgent(self.llm_provider)
        self.report_agent = ReportAgent(self.llm_provider)
        
        # Support services
        self.reporter = ReporterFactory.create()
        self.session_manager = SessionManager()
        self.log_manager = LogManager()
        self.current_session_id: Optional[str] = None
    
    def execute_assessment(self, 
                          attack_json_path: str,
                          max_iterations: int = None,
                          export_findings: bool = False,
                          start_from: str = None) -> Dict[str, Any]:
        """
        Execute a complete security assessment using cooperative agents
        
        Flow: Parse JSON → Recon → Analyze → Attack → Report
        Agents can request to go back to previous phases as needed
        
        Args:
            attack_json_path: Path to attack definition JSON file
            max_iterations: Maximum feedback loop iterations (defaults to MAX_COOPERATIVE_ITERATIONS)
            export_findings: Whether to export results to configured reporter
            start_from: Phase to start from (analysis, attack, report) - loads previous results
            
        Returns:
            Complete assessment results with report
        """
        # Use default from settings if not provided
        if max_iterations is None:
            max_iterations = settings.max_cooperative_iterations
        
        # 1. Initialize session (start logging early)
        self._initialize_session(attack_json_path, start_from)
        
        # 2. Validate prerequisites (with logging active)
        attack_def, target_config = self._validate_prerequisites(attack_json_path)
        
        # 3. Load or execute phases
        recon_data, analysis_data, attack_data = None, None, None
        
        if start_from:
            recon_data, analysis_data, attack_data = self._load_previous_phases(
                start_from, self.current_session_id, target_config.url
            )
        
        # 4. Execute reconnaissance (Phase 1)
        if not start_from or start_from == 'recon':
            recon_data = self._execute_reconnaissance(attack_def, target_config)
        
        # 5. Execute cooperative loop (Phases 2-3)
        iteration = self._execute_cooperative_loop(
            attack_def, target_config, recon_data, analysis_data, attack_data, 
            max_iterations, start_from
        )
        
        # Update data from loop results
        analysis_data = iteration['analysis_data']
        attack_data = iteration['attack_data']
        recon_data = iteration['recon_data']
        iteration_count = iteration['iteration']
        
        # 6. Generate report (Phase 4)
        report = self._execute_reporting(attack_def, recon_data, analysis_data, attack_data)
        
        # 7. Export to configured reporter if requested
        if export_findings:
            self._export_findings(report)
        
        # 8. Finalize and return results
        return self._finalize_assessment(
            attack_def, target_config, iteration_count,
            recon_data, analysis_data, attack_data, report
        )
    
    def _validate_prerequisites(self, attack_json_path: str):
        """Validate LLM provider, parse attack definition, and check target connectivity"""
        # Validate LLM provider
        if not self.llm_provider.is_available():
            error_msg = (
                "❌ CRITICAL ERROR: OpenAI client not initialized.\n"
                "Please set OPENAI_API_KEY in your .env file and restart the server.\n"
                "The assessment cannot proceed without a configured LLM provider."
            )
            print(f"\n{'='*60}")
            print(error_msg)
            print(f"{'='*60}\n")
            raise RuntimeError(error_msg)
        
        print(f"\n{'='*60}")
        print("AgentArx Cooperative Security Assessment")
        print(f"{'='*60}\n")
        
        # Parse attack definition
        print(f"📁 Loading attack definition: {Path(attack_json_path).name}")
        parsed_json = self.json_parser.parse_file(attack_json_path)
        attack_def = parsed_json.attack_definition
        target_config = settings.target_config
        
        if not target_config:
            raise ValueError("Target configuration not found. Please configure target_config.json")
        
        print(f"🎯 Target: {target_config.url}")
        print(f"🔍 Attack: {attack_def.name}")
        print(f"📋 Category: {attack_def.category}\n")
        
        # Check target connectivity
        print(f"🔌 Verifying target connectivity...")
        if not self._check_target_connectivity(target_config):
            error_msg = (
                f"❌ TARGET UNREACHABLE: Cannot connect to {target_config.url}\n"
                f"   Host: {target_config.host}\n"
                f"   Port: {target_config.port}\n\n"
                f"Please verify:\n"
                f"  1. The target system is running\n"
                f"  2. The IP address and port are correct\n"
                f"  3. No firewall is blocking access\n"
                f"  4. Network connectivity is available"
            )
            print(f"\n{'='*60}")
            print(error_msg)
            print(f"{'='*60}\n")
            raise RuntimeError(error_msg)
        
        print(f"✅ Target is accessible\n")
        
        return attack_def, target_config
    
    def _initialize_session(self, attack_json_path: str, start_from: str = None):
        """Create session and start logging"""
        attack_scenario_filename = Path(attack_json_path).name
        self.current_session_id = self.session_manager.create_session(
            attack_scenario_filename=attack_scenario_filename
        )
        
        # Start logging
        log_file = self.log_manager.start_logging(self.current_session_id)
        print(f"📝 Logging to: {log_file}")
        
        # Print session info
        if start_from:
            print(f"📌 Session ID: {self.current_session_id} (continuing existing session)\n")
            print(f"🔄 Starting from {start_from} phase (loading previous results)\n")
        else:
            print(f"📌 Session ID: {self.current_session_id} (new run)\n")
    
    def _execute_reconnaissance(self, attack_def, target_config):
        """Execute Phase 1: Reconnaissance"""
        print(f"{'='*60}")
        print("PHASE 1: RECONNAISSANCE")
        print(f"{'='*60}")
        
        recon_data = self.recon_agent.gather_intelligence(attack_def, target_config)
        
        # Save results
        recon_dict = self._dataclass_to_dict(recon_data)
        self.session_manager.save_phase_result(
            self.current_session_id, 
            'recon', 
            recon_dict,
            target_url=target_config.url,
            attack_name=attack_def.name,
            attack_id=attack_def.id
        )
        
        print(f"✅ Reconnaissance complete\n")
        return recon_data
    
    def _execute_cooperative_loop(self, attack_def, target_config, recon_data, 
                                   analysis_data, attack_data, max_iterations, start_from):
        """Execute Phases 2-3: Analysis and Attack with cooperative feedback loop"""
        iteration = 0
        
        while iteration < max_iterations:
            iteration += 1
            print(f"\n{'='*60}")
            print(f"ITERATION {iteration}/{max_iterations}")
            print(f"{'='*60}\n")
            
            # Phase 2: Analysis (start_from only applies to first iteration)
            if not start_from or start_from == 'analysis' or iteration > 1:
                if recon_data is None:
                    raise RuntimeError("Cannot execute analysis phase: recon_data is None.")
                
                print(f"{'='*60}")
                print("PHASE 2: ANALYSIS & PLANNING")
                print(f"{'='*60}")
                analysis_data = self.analyze_agent.analyze_and_plan(attack_def, recon_data)
                
                # Check if more recon needed
                if analysis_data.needs_more_recon:
                    print(f"\n🔄 Analysis requests additional reconnaissance:")
                    for request in analysis_data.recon_requests:
                        print(f"   - {request}")
                    print()
                    recon_data = self.recon_agent.gather_additional(
                        analysis_data.recon_requests, recon_data, target_config
                    )
                    # Re-run analysis with updated recon data (don't increment iteration)
                    print(f"\n{'='*60}")
                    print("PHASE 2: ANALYSIS & PLANNING (Re-analyzing with new data)")
                    print(f"{'='*60}")
                    analysis_data = self.analyze_agent.analyze_and_plan(attack_def, recon_data)
                
                # Check if should skip to report
                if analysis_data.skip_to_report:
                    print(f"\n⏭️  No exploitable vulnerabilities found, proceeding to report")
                    print(f"   Reason: {analysis_data.notes}\n")
                    attack_data = AttackData(
                        attack_complete=True,
                        notes="Attack phase skipped - no exploitable vulnerabilities identified"
                    )
                    break
                
                # Save analysis results
                analysis_dict = self._dataclass_to_dict(analysis_data)
                self.session_manager.save_phase_result(
                    self.current_session_id, 'analysis', analysis_dict,
                    target_url=target_config.url,
                    attack_name=attack_def.name,
                    attack_id=attack_def.id
                )
                print(f"✅ Analysis complete\n")
            
            # Phase 3: Attack (start_from only applies to first iteration)
            if not start_from or start_from in ['analysis', 'attack'] or iteration > 1:
                if recon_data is None or analysis_data is None:
                    raise RuntimeError("Cannot execute attack phase: missing prerequisite data.")
                
                print(f"{'='*60}")
                print("PHASE 3: ATTACK EXECUTION")
                print(f"{'='*60}")
                attack_data = self.attack_agent.execute_attack(attack_def, recon_data, analysis_data)
                
                # Check if attack requests more work
                if attack_data.needs_more_recon:
                    print(f"\n🔄 Attack agent requests additional reconnaissance")
                    recon_requests = [r.specific_tasks for r in attack_data.requests 
                                     if r.request_type == 'more_recon']
                    recon_requests = [task for sublist in recon_requests for task in sublist]
                    recon_data = self.recon_agent.gather_additional(
                        recon_requests, recon_data, target_config
                    )
                    continue
                
                if attack_data.needs_reanalysis:
                    print(f"\n🔄 Attack agent requests reanalysis with new findings")
                    continue
                
                # Save attack results
                attack_dict = self._dataclass_to_dict(attack_data)
                self.session_manager.save_phase_result(
                    self.current_session_id, 'attack', attack_dict,
                    target_url=target_config.url,
                    attack_name=attack_def.name,
                    attack_id=attack_def.id
                )
                print(f"✅ Attack execution complete\n")
                break
        
        return {
            'iteration': iteration,
            'recon_data': recon_data,
            'analysis_data': analysis_data,
            'attack_data': attack_data
        }
    
    def _execute_reporting(self, attack_def, recon_data, analysis_data, attack_data):
        """Execute Phase 4: Report Generation"""
        if recon_data is None or analysis_data is None or attack_data is None:
            raise RuntimeError("Cannot generate report: missing phase data.")
        
        print(f"{'='*60}")
        print("PHASE 4: REPORT GENERATION")
        print(f"{'='*60}")
        
        report = self.report_agent.generate_comprehensive_report(
            attack_def, recon_data, analysis_data, attack_data
        )
        
        print(f"✅ Report generated\n")
        return report
    
    def _export_findings(self, report):
        """Export report to configured vulnerability tracker"""
        print(f"{'='*60}")
        print(f"EXPORTING TO {self.reporter.get_name().upper()}")
        print(f"{'='*60}\n")
        
        export_success = self.reporter.submit_report(report)
        report['reporter_export'] = export_success
        
        if export_success:
            print(f"✅ Successfully exported to {self.reporter.get_name()}\n")
        else:
            print(f"❌ Failed to export to {self.reporter.get_name()}\n")
    
    def _finalize_assessment(self, attack_def, target_config, iteration_count,
                            recon_data, analysis_data, attack_data, report):
        """Save complete results and cleanup"""
        results = {
            'session_id': self.current_session_id,
            'attack_name': attack_def.name,
            'attack_id': attack_def.id,
            'target_url': target_config.url,
            'iterations': iteration_count,
            'status': 'completed',
            'recon_data': self._dataclass_to_dict(recon_data),
            'analysis_data': self._dataclass_to_dict(analysis_data),
            'attack_data': self._dataclass_to_dict(attack_data),
            'report': report
        }
        
        result_file = self.session_manager.save_assessment(self.current_session_id, results)
        
        print(f"\n{'='*60}")
        print(f"✅ ASSESSMENT COMPLETE")
        print(f"Session: {self.current_session_id}")
        print(f"Results saved: {result_file}")
        print(f"{'='*60}\n")
        
        # Stop logging
        self.log_manager.stop_logging()
        
        return results
    
    def _dataclass_to_dict(self, obj: Any) -> Dict[str, Any]:
        """Convert dataclass to dict for JSON serialization"""
        if hasattr(obj, '__dataclass_fields__'):
            from dataclasses import asdict
            return asdict(obj)
        return obj
    
    def _load_previous_phases(self, start_from: str, session_id: str, target_url: str):
        """
        Load previous phase results based on start_from parameter.
        Validates that loaded results match the expected session.
        
        Args:
            start_from: Phase to start from (analysis, attack, report)
            session_id: Expected session ID (deterministic)
            target_url: Expected target URL for validation
            
        Returns:
            Tuple of (recon_data, analysis_data, attack_data)
            
        Raises:
            FileNotFoundError: If required phase file doesn't exist
            ValueError: If session or target validation fails
        """
        recon_data = None
        analysis_data = None
        attack_data = None
        
        # Load recon if starting from analysis or later
        if start_from in ['analysis', 'attack', 'report']:
            recon_dict = self.session_manager.load_phase_result(
                'recon',
                expected_session_id=session_id,
                expected_target_url=target_url
            )
            if not recon_dict:
                raise FileNotFoundError(
                    f"Cannot start from {start_from}: recon.json not found. "
                    "Run full assessment first or start from recon phase."
                )
            recon_data = self.session_manager.reconstruct_dataclass(ReconData, recon_dict)
        
        # Load analysis if starting from attack or report
        if start_from in ['attack', 'report']:
            analysis_dict = self.session_manager.load_phase_result(
                'analysis',
                expected_session_id=session_id,
                expected_target_url=target_url
            )
            if not analysis_dict:
                raise FileNotFoundError(
                    f"Cannot start from {start_from}: analysis.json not found. "
                    "Run full assessment first or start from analysis phase."
                )
            analysis_data = self.session_manager.reconstruct_dataclass(AnalysisData, analysis_dict)
        
        # Load attack if starting from report
        if start_from == 'report':
            attack_dict = self.session_manager.load_phase_result(
                'attack',
                expected_session_id=session_id,
                expected_target_url=target_url
            )
            if not attack_dict:
                raise FileNotFoundError(
                    f"Cannot start from report: attack.json not found. "
                    "Run full assessment first or start from attack phase."
                )
            attack_data = self.session_manager.reconstruct_dataclass(AttackData, attack_dict)
        
        return recon_data, analysis_data, attack_data
    
    def _check_target_connectivity(self, target_config: TargetConfig, timeout: int = 5) -> bool:
        """
        Check if target is accessible before starting assessment
        
        Args:
            target_config: Target configuration
            timeout: Connection timeout in seconds
            
        Returns:
            True if target is accessible, False otherwise
        """
        import socket
        import urllib.request
        import urllib.error
        
        # Try socket connection first (faster)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target_config.host, target_config.port))
            sock.close()
            
            if result != 0:
                return False
            
            # Socket connected, try HTTP request to verify it's actually responding
            try:
                req = urllib.request.Request(target_config.url, method='HEAD')
                urllib.request.urlopen(req, timeout=timeout)
                return True
            except (urllib.error.URLError, urllib.error.HTTPError) as e:
                # Port is open but HTTP might not be responding
                # Log warning but consider it accessible for low-level testing
                print(f"⚠️  Warning: Port {target_config.port} is open but HTTP check failed: {e}")
                return True
            except socket.timeout:
                print(f"⚠️  Warning: HTTP request timed out after {timeout}s")
                return False
                
        except (socket.timeout, socket.error, OSError) as e:
            print(f"❌ Socket connection failed: {e}")
            return False
        except Exception as e:
            # Catch any unexpected errors in connectivity check
            print(f"❌ Unexpected error during connectivity check: {e}")
            return False
