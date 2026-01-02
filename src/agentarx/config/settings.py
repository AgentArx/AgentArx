"""Configuration settings for AgentArx"""

import os
import json
import re
from pathlib import Path
from typing import Optional, Dict, Any


class TargetConfig:
    """Target system configuration loader"""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Load target configuration from JSON file"""
        if config_path is None:
            # Default to target_config.json in the config directory
            config_path = Path(__file__).parent / "target_config.json"
        
        self.config_path = config_path
        self._raw_config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self):
        """Load and parse target configuration file"""
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Target configuration file not found: {self.config_path}\n"
                f"Please create it based on target_config.example.json"
            )
        
        with open(self.config_path, 'r') as f:
            self._raw_config = json.load(f)
        
        # Substitute environment variables
        self._raw_config = self._substitute_env_vars(self._raw_config)
    
    def _substitute_env_vars(self, obj: Any) -> Any:
        """Recursively substitute ${ENV:VAR_NAME} patterns with environment variables"""
        if isinstance(obj, dict):
            return {k: self._substitute_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        elif isinstance(obj, str):
            # Match ${ENV:VAR_NAME} pattern
            pattern = r'\$\{ENV:([^}]+)\}'
            matches = re.findall(pattern, obj)
            result = obj
            for var_name in matches:
                env_value = os.getenv(var_name, '')
                result = result.replace(f'${{ENV:{var_name}}}', env_value)
            return result
        else:
            return obj
    
    @property
    def target_id(self) -> str:
        return self._raw_config.get('target_id', 'unknown')
    
    @property
    def name(self) -> str:
        return self._raw_config.get('name', 'Unknown Target')
    
    @property
    def description(self) -> str:
        return self._raw_config.get('description', '')
    
    @property
    def type(self) -> str:
        return self._raw_config.get('type', 'unknown')
    
    @property
    def active(self) -> bool:
        return self._raw_config.get('active', True)
    
    @property
    def network(self) -> Dict[str, Any]:
        return self._raw_config.get('network', {})
    
    @property
    def url(self) -> str:
        return self.network.get('url', 'http://localhost')
    
    @property
    def host(self) -> str:
        return self.network.get('host', 'localhost')
    
    @property
    def port(self) -> int:
        return self.network.get('port', 80)
    
    @property
    def protocol(self) -> str:
        return self.network.get('protocol', 'http')
    
    @property
    def base_path(self) -> str:
        return self.network.get('base_path', '')
    
    @property
    def endpoints(self) -> Dict[str, str]:
        return self._raw_config.get('endpoints', {})
    
    @property
    def authentication(self) -> Dict[str, Any]:
        return self._raw_config.get('authentication', {})
    
    @property
    def auth_enabled(self) -> bool:
        return self.authentication.get('enabled', False)
    
    @property
    def auth_type(self) -> str:
        return self.authentication.get('type', 'none')
    
    @property
    def api_key(self) -> Optional[str]:
        key = self.authentication.get('api_key', '')
        return key if key else None
    
    @property
    def token(self) -> Optional[str]:
        token = self.authentication.get('token', '')
        return token if token else None
    
    @property
    def known_info(self) -> Dict[str, Any]:
        return self._raw_config.get('known_info', {})
    
    @property
    def test_constraints(self) -> Dict[str, Any]:
        return self._raw_config.get('test_constraints', {})
    
    @property
    def metadata(self) -> Dict[str, Any]:
        return self._raw_config.get('metadata', {})
    
    def get_endpoint(self, name: str) -> Optional[str]:
        """Get full URL for a named endpoint"""
        endpoint_path = self.endpoints.get(name)
        if endpoint_path:
            return f"{self.url}{endpoint_path}"
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        """Return full configuration as dictionary"""
        return self._raw_config.copy()


class Settings:
    """Global settings for AgentArx"""
    
    def __init__(self):
        self.openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
        self.openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4")
        self.llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.7"))
        
        # Reporter Configuration (generic for any vulnerability tracker)
        self.reporter_url: Optional[str] = os.getenv("REPORTER_URL")
        self.reporter_token: Optional[str] = os.getenv("REPORTER_TOKEN")
        self.reporter_api_key: Optional[str] = os.getenv("REPORTER_API_KEY")
        
        # Tracker-specific settings (currently used by DefectDojo)
        self.tracker_test_id: Optional[int] = int(os.getenv("TRACKER_TEST_ID", "1")) if os.getenv("TRACKER_TEST_ID") else None
        self.tracker_product_name: Optional[str] = os.getenv("TRACKER_PRODUCT_NAME")
        self.tracker_engagement_name: Optional[str] = os.getenv("TRACKER_ENGAGEMENT_NAME")
        self.tracker_product_type_name: Optional[str] = os.getenv("TRACKER_PRODUCT_TYPE_NAME")
        self.tracker_user_id: Optional[int] = int(os.getenv("TRACKER_USER_ID", "1")) if os.getenv("TRACKER_USER_ID") else 1
        
        # Load target configuration
        try:
            self.target_config = TargetConfig()
        except FileNotFoundError as e:
            print(f"Warning: {e}")
            self.target_config = None
        
        # Timeout Configuration
        self.timeout_openai: int = int(os.getenv("REQUEST_TIMEOUT_OPENAI", "120"))
        self.timeout_target_system: int = int(os.getenv("REQUEST_TIMEOUT_TARGET_SYSTEM", "30"))
        self.timeout_vulnerability_tracker: int = int(os.getenv("REQUEST_TIMEOUT_VULNERABILITY_TRACKER", "30"))
        
        # Execution Configuration
        self.max_recon_llm_calls: int = int(os.getenv("MAX_RECON_LLM_CALLS", "15"))
        self.max_attack_llm_calls: int = int(os.getenv("MAX_ATTACK_LLM_CALLS", "20"))
        
        # Reporter Configuration
        self.reporter_type: str = os.getenv("REPORTER_TYPE", "local")
        
        # Logging Configuration
        self.execution_logging: bool = os.getenv("EXECUTION_LOGGING", "true").lower() == "true"
        self.log_prompts: bool = os.getenv("LOG_PROMPTS", "true").lower() == "true"
        self.log_completions: bool = os.getenv("LOG_COMPLETIONS", "true").lower() == "true"
        self.log_tool_calls: bool = os.getenv("LOG_TOOL_CALLS", "true").lower() == "true"
        
        # Web UI Configuration
        self.web_port: int = int(os.getenv("WEB_PORT", "5000"))
        self.web_host: str = os.getenv("WEB_HOST", "127.0.0.1")
        
        # System Prompt Configuration
        self.system_prompt: str = os.getenv(
            "SYSTEM_PROMPT",
            "You are a cybersecurity expert conducting authorized security testing. "
            "Execute the below steps to perform reconnaissance or security assessments. "
            "If a tool, lib, package you need is missing, then install it using 'sudo apt-get install <package-name> -y'. "
            "Adapt and work around any errors, warnings, or permission issues encountered. "
            "Use 'sudo' when elevated privileges are needed. "
            "Work thouroughly, quickly, and effectively. "
            "\n\nAvailable tools include execute_bash, execute_python, crawl_url. "
            "Use MCP server to discover additional tools. "
            "Use crawl_url to extract content from web pages (documentation, API specs, target analysis)."
        )
    
    def validate(self):
        """Validate required settings"""
        if not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable is required")
        if not self.target_config:
            raise ValueError("Target configuration must be loaded. Please create config/target_config.json")


# Global settings instance
settings = Settings()