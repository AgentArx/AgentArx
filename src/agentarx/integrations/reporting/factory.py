"""Factory for creating vulnerability reporters"""

from typing import Optional
from .base import BaseReporter
from .defectdojo import DefectDojoReporter
from .local import LocalFileReporter
from .noop import NoOpReporter
from ...config.settings import settings


class ReporterFactory:
    """Factory for creating reporter instances based on configuration"""
    
    @staticmethod
    def create(reporter_type: Optional[str] = None) -> BaseReporter:
        """
        Create a reporter instance
        
        Args:
            reporter_type: Type of reporter to create. If None, uses settings.reporter_type
            
        Returns:
            Reporter instance
            
        Raises:
            ValueError: If reporter type is unknown
        """
        reporter_type = reporter_type or settings.reporter_type
        
        if reporter_type == "defectdojo":
            return DefectDojoReporter()
        elif reporter_type == "local":
            return LocalFileReporter()
        elif reporter_type == "none":
            return NoOpReporter()
        else:
            raise ValueError(
                f"Unknown reporter type: {reporter_type}. "
                f"Valid options: defectdojo, local, none"
            )
    
    @staticmethod
    def get_available_reporters() -> list:
        """Get list of available reporter types"""
        return ["defectdojo", "local", "none"]
