"""Test cases for MCP tool functionality"""

import pytest
from agentarx.mcp_client import MCPClient


@pytest.fixture
def mcp_client():
    """Create and start MCP client for tests"""
    client = MCPClient()
    client.start()
    yield client
    client.stop()


def test_execute_bash_success(mcp_client):
    """Test successful bash command execution"""
    result = mcp_client.call_tool("execute_bash", {"command": "echo 'test'"})
    
    assert result['success'] is True
    assert 'test' in result['stdout']
    assert result['return_code'] == 0


def test_execute_bash_failure(mcp_client):
    """Test bash command that fails"""
    result = mcp_client.call_tool("execute_bash", {"command": "nonexistent_cmd_xyz"})
    
    assert result['success'] is False
    assert result['return_code'] != 0


def test_execute_python_success(mcp_client):
    """Test successful Python execution"""
    result = mcp_client.call_tool("execute_python", {"code": "print('hello')"})
    
    assert result['success'] is True
    assert 'hello' in result['stdout']


def test_execute_python_exception(mcp_client):
    """Test Python code with exception"""
    result = mcp_client.call_tool("execute_python", {"code": "1 / 0"})
    
    assert result['success'] is False
    assert result['exception_type'] == 'ZeroDivisionError'


def test_execute_python_syntax_error(mcp_client):
    """Test Python code with syntax error"""
    result = mcp_client.call_tool("execute_python", {"code": "print('unclosed"})
    
    assert result['success'] is False
    assert 'SyntaxError' in result['exception_type']


def test_list_tools(mcp_client):
    """Test listing available tools"""
    tools = mcp_client.list_tools()
    
    assert len(tools) > 0
    tool_names = [t.get('name') for t in tools]
    assert 'execute_bash' in tool_names
    assert 'execute_python' in tool_names
    assert 'web_search' in tool_names
    assert 'crawl_url' in tool_names