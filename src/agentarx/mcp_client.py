"""MCP Client for communicating with AgentArx MCP Server"""

import subprocess
import json
import atexit
from typing import Dict, Any, Optional, List
from pathlib import Path


class MCPClient:
    """Client for communicating with MCP server via stdio"""
    
    def __init__(self):
        self.process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._initialized = False
        
    def start(self):
        """Start the MCP server subprocess"""
        if self.process is not None:
            return
        
        # Get path to MCP server
        server_path = Path(__file__).parent / "mcp_server" / "server.py"
        
        # Start server process with stdio communication
        self.process = subprocess.Popen(
            ["python", str(server_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        )
        
        # Register cleanup on exit
        atexit.register(self.stop)
        
        # Initialize the MCP connection
        self._initialize()
        
    def _initialize(self):
        """Initialize the MCP connection with handshake"""
        if self._initialized or self.process is None:
            return
            
        self._request_id += 1
        
        init_request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "agentarx-client",
                    "version": "1.0"
                }
            }
        }
        
        try:
            request_json = json.dumps(init_request) + "\n"
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            response_line = self.process.stdout.readline()
            if not response_line:
                raise RuntimeError("MCP server closed during initialization")
            
            response = json.loads(response_line)
            
            if "error" in response:
                error = response["error"]
                raise RuntimeError(f"MCP initialization error: {error.get('message', 'Unknown error')}")
            
            self._initialized = True
        except Exception as e:
            raise RuntimeError(f"Failed to initialize MCP client: {e}")
        
    def stop(self):
        """Stop the MCP server subprocess"""
        if self.process is not None:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                self.process.kill()
            finally:
                self.process = None
    
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool on the MCP server
        
        Args:
            tool_name: Name of the tool to call
            arguments: Tool arguments
            
        Returns:
            Tool result dictionary
        """
        if self.process is None:
            self.start()
        
        self._request_id += 1
        
        # Construct MCP request
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        try:
            # Send request
            request_json = json.dumps(request) + "\n"
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            # Read response
            response_line = self.process.stdout.readline()
            if not response_line:
                raise RuntimeError("MCP server closed connection")
            
            response = json.loads(response_line)
            
            # Check for errors
            if "error" in response:
                error = response["error"]
                raise RuntimeError(f"MCP error: {error.get('message', 'Unknown error')}")
            
            # Parse result from FastMCP format
            result = response.get("result", {})
            
            # FastMCP wraps results in content array
            if "content" in result and len(result["content"]) > 0:
                content_item = result["content"][0]
                if content_item.get("type") == "text":
                    # Parse the JSON string in the text field
                    try:
                        return json.loads(content_item["text"])
                    except (json.JSONDecodeError, KeyError):
                        return content_item
            
            # Return raw result if not in expected format
            return result
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_tools(self) -> List[Dict[str, Any]]:
        """
        List available tools from MCP server
        
        Returns:
            List of tool definitions
        """
        if self.process is None:
            self.start()
        
        self._request_id += 1
        
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "tools/list"
        }
        
        try:
            request_json = json.dumps(request) + "\n"
            self.process.stdin.write(request_json)
            self.process.stdin.flush()
            
            response_line = self.process.stdout.readline()
            if not response_line:
                return []
            
            response = json.loads(response_line)
            
            if "error" in response:
                return []
            
            return response.get("result", {}).get("tools", [])
            
        except Exception as e:
            print(f"Error listing tools: {e}")
            return []
    
    def get_tools_for_llm(self) -> List[Dict[str, Any]]:
        """
        Get tool definitions formatted for LLM function calling
        
        Returns:
            List of tool definitions in OpenAI function format
        """
        tools = self.list_tools()
        
        llm_tools = []
        for tool in tools:
            llm_tool = {
                "type": "function",
                "function": {
                    "name": tool.get("name"),
                    "description": tool.get("description", ""),
                    "parameters": tool.get("inputSchema", {})
                }
            }
            llm_tools.append(llm_tool)
        
        return llm_tools


# Global MCP client instance
_mcp_client = None


def get_mcp_client() -> MCPClient:
    """Get or create the global MCP client instance"""
    global _mcp_client
    if _mcp_client is None:
        _mcp_client = MCPClient()
        _mcp_client.start()
    return _mcp_client
