"""Base LLM provider interface"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional, Union


class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers"""
    
    @abstractmethod
    def chat(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """
        Send chat messages to the LLM and return response
        
        Args:
            messages: List of message dicts with 'role' and 'content' keys
            **kwargs: Additional provider-specific parameters
            
        Returns:
            String response from the LLM
        """
        pass
    
    def chat_with_tools(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Dict[str, Any]:
        """
        Send chat messages with tool support and return structured response
        
        Args:
            messages: List of message dicts with 'role' and 'content' keys
            tools: Optional list of tool schemas for function calling
            **kwargs: Additional provider-specific parameters
            
        Returns:
            Dict with 'content' and optional 'tool_calls' keys
        """
        # Default implementation falls back to regular chat
        response = self.chat(messages, **kwargs)
        return {"content": response, "tool_calls": None}
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if the provider is properly configured and available"""
        pass