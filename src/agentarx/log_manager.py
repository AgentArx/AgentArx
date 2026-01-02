"""Log manager for capturing stdout to files"""

import sys
from pathlib import Path
from typing import Optional, TextIO
from datetime import datetime


class LogManager:
    """Manages log files for assessment sessions"""
    
    def __init__(self, base_path: str = "logs"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.current_log_file: Optional[Path] = None
        self.original_stdout: Optional[TextIO] = None
        self.log_file_handle: Optional[TextIO] = None
    
    def start_logging(self, session_id: str) -> Path:
        """
        Start logging to file for a session.
        Redirects stdout to both console and log file.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Path to log file
        """
        # Stop any existing logging first to prevent nesting
        if self.log_file_handle is not None:
            self.stop_logging()
        
        self.current_log_file = self.base_path / f"{session_id}.log"
        
        # Save original stdout (before any TeeWriter wrapping)
        if not isinstance(sys.stdout, TeeWriter):
            self.original_stdout = sys.stdout
        else:
            # Already wrapped, find the real stdout
            self.original_stdout = sys.__stdout__
        
        # Open log file in append mode
        self.log_file_handle = open(self.current_log_file, 'a', encoding='utf-8')
        
        # Write session header
        header = f"\n{'='*60}\n"
        header += f"Session: {session_id}\n"
        header += f"Started: {datetime.now().isoformat()}\n"
        header += f"{'='*60}\n\n"
        self.log_file_handle.write(header)
        self.log_file_handle.flush()
        
        # Replace stdout with tee that writes to both
        sys.stdout = TeeWriter(self.original_stdout, self.log_file_handle)
        
        return self.current_log_file
    
    def stop_logging(self):
        """Stop logging and restore original stdout"""
        if self.original_stdout:
            sys.stdout = self.original_stdout
            self.original_stdout = None
        
        if self.log_file_handle:
            # Write session footer
            footer = f"\n{'='*60}\n"
            footer += f"Completed: {datetime.now().isoformat()}\n"
            footer += f"{'='*60}\n"
            self.log_file_handle.write(footer)
            self.log_file_handle.flush()
            self.log_file_handle.close()
            self.log_file_handle = None
    
    def get_log_file(self, session_id: str) -> Optional[Path]:
        """Get path to log file for a session"""
        log_file = self.base_path / f"{session_id}.log"
        return log_file if log_file.exists() else None
    
    def tail_log(self, session_id: str, lines: int = 100) -> list:
        """Get last N lines from log file"""
        log_file = self.get_log_file(session_id)
        if not log_file:
            return []
        
        with open(log_file, 'r', encoding='utf-8') as f:
            return f.readlines()[-lines:]
    
    def read_log(self, session_id: str) -> str:
        """Read entire log file"""
        log_file = self.get_log_file(session_id)
        if not log_file:
            return ""
        
        with open(log_file, 'r', encoding='utf-8') as f:
            return f.read()


class TeeWriter:
    """Writer that sends output to multiple destinations"""
    
    def __init__(self, *writers):
        self.writers = writers
    
    def write(self, text):
        for writer in self.writers:
            try:
                writer.write(text)
                writer.flush()  # Flush immediately for real-time log streaming
            except (OSError, ValueError):
                # Handle closed file handles gracefully
                pass
    
    def flush(self):
        for writer in self.writers:
            try:
                writer.flush()
            except (OSError, ValueError):
                # Handle closed file handles gracefully
                pass
    
    def isatty(self):
        # Return False to prevent issues with progress bars
        return False
