"""OpenAI LLM provider implementation"""

import json
from typing import Dict, List, Any, Optional
from openai import OpenAI
from .base import BaseLLMProvider
from ..config.settings import settings


class OpenAIProvider(BaseLLMProvider):
    """OpenAI ChatGPT provider"""
    
    def __init__(self):
        self.client = None
        if settings.openai_api_key:
            try:
                self.client = OpenAI(
                    api_key=settings.openai_api_key,
                    timeout=settings.timeout_openai
                )
            except Exception as e:
                print(f"Warning: Failed to initialize OpenAI client: {e}")
                self.client = None
    
    def chat(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Send chat messages to OpenAI and return response"""
        if not self.client:
            raise ValueError("OpenAI client not initialized. Check OPENAI_API_KEY.")
        
        # Prepare parameters
        temperature_value = kwargs.get('temperature', 0.7)
        response_format = kwargs.get('response_format')
        
        # Base parameters (no max_tokens to allow maximum context window)
        chat_params = {
            'model': settings.openai_model,
            'messages': messages,
            'timeout': settings.timeout_openai
        }
        
        # Add response_format if specified (JSON mode)
        if response_format:
            chat_params['response_format'] = response_format
        
        # Try different parameter combinations with error handling
        try:
            # First attempt: custom temperature
            chat_params['temperature'] = temperature_value
            response = self.client.chat.completions.create(**chat_params)
        except Exception as e:
            error_str = str(e)
            
            # Check for rate limit or token limit errors
            if 'rate_limit' in error_str.lower() or 'rate limit' in error_str.lower():
                raise RuntimeError(f"OpenAI rate limit exceeded: {error_str}")
            elif 'maximum context length' in error_str.lower() or 'token limit' in error_str.lower():
                raise RuntimeError(f"Context window overflow: {error_str}")
            elif 'invalid model' in error_str.lower() or 'model not found' in error_str.lower():
                raise RuntimeError(f"Invalid model '{settings.openai_model}'. Use: gpt-4, gpt-4o, gpt-4o-mini, gpt-4-turbo, or gpt-3.5-turbo")
            
            # Handle response_format not supported (older models or o1 models)
            if "response_format" in error_str and ("not supported" in error_str or "invalid" in error_str.lower()):
                print(f"Warning: response_format not supported by {settings.openai_model}, falling back to prompt engineering")
                if 'response_format' in chat_params:
                    del chat_params['response_format']
                try:
                    response = self.client.chat.completions.create(**chat_params)
                except Exception as e2:
                    raise e2
            elif 'temperature' in error_str and 'does not support' in error_str:
                # Remove temperature parameter and try with default
                del chat_params['temperature']
                try:
                    response = self.client.chat.completions.create(**chat_params)
                except Exception as e2:
                    raise e2
            else:
                raise e
        
        return response.choices[0].message.content
    
    def chat_with_tools(self, messages: List[Dict[str, str]], tools: Optional[List[Dict[str, Any]]] = None, **kwargs) -> Dict[str, Any]:
        """Send chat messages with tool support and return structured response"""
        if not self.client:
            raise ValueError("OpenAI client not initialized. Check OPENAI_API_KEY.")
        
        # Prepare parameters
        temperature_value = kwargs.get('temperature', settings.llm_temperature)
        response_format = kwargs.get('response_format')
        
        # Base parameters (no max_tokens to allow maximum context window)
        chat_params = {
            'model': settings.openai_model,
            'messages': messages,
            'timeout': settings.timeout_openai
        }
        
        # Add tools if provided (response_format cannot be used with tools)
        if tools:
            chat_params['tools'] = tools
            chat_params['tool_choice'] = 'auto'
        elif response_format:
            # Only add response_format when not using tools
            chat_params['response_format'] = response_format
        
        # Handle different parameter combinations
        try:
            # First attempt: custom temperature
            chat_params['temperature'] = temperature_value
            response = self.client.chat.completions.create(**chat_params)
        except Exception as e:
            error_str = str(e)
            
            # Check for rate limit or token limit errors
            if 'rate_limit' in error_str.lower() or 'rate limit' in error_str.lower():
                raise RuntimeError(f"OpenAI rate limit exceeded: {error_str}")
            elif 'maximum context length' in error_str.lower() or 'token limit' in error_str.lower():
                raise RuntimeError(f"Context window overflow: {error_str}")
            elif 'invalid model' in error_str.lower() or 'model not found' in error_str.lower():
                raise RuntimeError(f"Invalid model '{settings.openai_model}'. Use: gpt-4, gpt-4o, gpt-4o-mini, gpt-4-turbo, or gpt-3.5-turbo")
            
            # Handle response_format not supported (older models or o1 models)
            if "response_format" in error_str and ("not supported" in error_str or "invalid" in error_str.lower()):
                print(f"Warning: response_format not supported by {settings.openai_model}, falling back to prompt engineering")
                if 'response_format' in chat_params:
                    del chat_params['response_format']
                try:
                    response = self.client.chat.completions.create(**chat_params)
                except Exception as e2:
                    raise e2
            elif 'temperature' in error_str and 'does not support' in error_str:
                # Remove temperature parameter and try with default
                del chat_params['temperature']
                try:
                    response = self.client.chat.completions.create(**chat_params)
                except Exception as e2:
                    raise e2
            else:
                raise e
        
        message = response.choices[0].message
        
        # Structure the response
        result = {
            "content": message.content or "",
            "tool_calls": None
        }
        
        # Handle tool calls if present
        if hasattr(message, 'tool_calls') and message.tool_calls:
            result["tool_calls"] = []
            for tool_call in message.tool_calls:
                result["tool_calls"].append({
                    "id": tool_call.id,
                    "type": "function",
                    "function": {
                        "name": tool_call.function.name,
                        "arguments": tool_call.function.arguments
                    }
                })
        
        return result
    
    def is_available(self) -> bool:
        """Check if OpenAI provider is available"""
        return self.client is not None and settings.openai_api_key is not None