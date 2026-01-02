"""Base reporter interface for vulnerability reporting systems"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BaseReporter(ABC):
    """Abstract base class for vulnerability reporters"""
    
    @abstractmethod
    def submit_report(self, report: Dict[str, Any]) -> bool:
        """
        Submit a security assessment report
        
        Args:
            report: Comprehensive security report
            
        Returns:
            True if submission successful, False otherwise
        """
        pass
    
    @abstractmethod
    def is_configured(self) -> bool:
        """
        Check if reporter is properly configured
        
        Returns:
            True if configured, False otherwise
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """
        Get reporter name for logging
        
        Returns:
            Reporter name
        """
        pass
