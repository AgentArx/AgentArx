"""Local file reporter - saves reports to disk"""

import json
from pathlib import Path
from typing import Dict, Any
from datetime import datetime
from .base import BaseReporter


class LocalFileReporter(BaseReporter):
    """Reporter that saves reports to local files"""
    
    def __init__(self, output_dir: str = "results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def submit_report(self, report: Dict[str, Any]) -> bool:
        """Save report to local file"""
        try:
            # Generate filename with timestamp
            report_id = report.get('report_id', 'unknown')
            # Use fixed filename per report_id (no timestamp)
            filename = f"report_{report_id}.json"
            filepath = self.output_dir / filename

            # Save report
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)

            print(f"✅ Report saved to: {filepath}")
            return True

        except Exception as e:
            print(f"❌ Failed to save report: {e}")
            return False
    
    def is_configured(self) -> bool:
        """Local reporter is always configured"""
        return True
    
    def get_name(self) -> str:
        return "LocalFile"
