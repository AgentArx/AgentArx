"""No-op reporter - disables reporting"""

from typing import Dict, Any
from .base import BaseReporter


class NoOpReporter(BaseReporter):
    """Reporter that does nothing - useful for disabling reporting"""
    
    def submit_report(self, report: Dict[str, Any]) -> bool:
        """Do nothing"""
        print("ℹ️  Reporting disabled (reporter_type=none)")
        return True
    
    def is_configured(self) -> bool:
        """Always configured"""
        return True
    
    def get_name(self) -> str:
        return "None"
