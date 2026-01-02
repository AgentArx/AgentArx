"""FastMCP Server for AgentArx Tools"""

import subprocess
import sys
from typing import Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("agentarx-tools")


# ============================================================================
# Tool Schemas
# ============================================================================

class BashExecuteRequest(BaseModel):
    """Request schema for bash command execution"""
    command: str = Field(..., description="Bash command to execute")
    timeout: Optional[int] = Field(300, description="Timeout in seconds")


class BashExecuteResponse(BaseModel):
    """Response schema for bash command execution"""
    stdout: str = Field(..., description="Standard output from command")
    stderr: str = Field(..., description="Standard error from command")
    return_code: int = Field(..., description="Command exit code")
    success: bool = Field(..., description="Whether command succeeded")


class PythonExecuteRequest(BaseModel):
    """Request schema for Python code execution"""
    code: str = Field(..., description="Python code to execute")
    timeout: Optional[int] = Field(300, description="Timeout in seconds")


class PythonExecuteResponse(BaseModel):
    """Response schema for Python code execution"""
    stdout: str = Field(..., description="Standard output")
    stderr: str = Field(..., description="Standard error")
    success: bool = Field(..., description="Whether execution succeeded")
    exception_type: Optional[str] = Field(None, description="Exception type if failed")


class WebSearchRequest(BaseModel):
    """Request schema for web search"""
    query: str = Field(..., description="Search query")
    max_results: int = Field(10, description="Maximum number of results")


class WebSearchResponse(BaseModel):
    """Response schema for web search"""
    results: list = Field(..., description="Search results")
    success: bool = Field(..., description="Whether search succeeded")


class CrawlRequest(BaseModel):
    """Request schema for web crawling"""
    url: str = Field(..., description="URL to crawl")
    extract_type: str = Field("markdown", description="Type of extraction: markdown, text, or links")


class CrawlResponse(BaseModel):
    """Response schema for web crawling"""
    content: Optional[str] = Field(None, description="Extracted content")
    success: bool = Field(..., description="Whether crawl succeeded")
    error: Optional[str] = Field(None, description="Error message if failed")


# ============================================================================
# Tool Implementations
# ============================================================================

@mcp.tool()
def execute_bash(command: str, timeout: int = 300) -> dict:
    """
    Execute a bash command and return the output.
    
    Args:
        command: Bash command to execute
        timeout: Timeout in seconds (default: 300)
        
    Returns:
        Dictionary with stdout, stderr, return_code, and success status
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode,
            "success": result.returncode == 0
        }
    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds",
            "return_code": -1,
            "success": False
        }
    except Exception as e:
        return {
            "stdout": "",
            "stderr": f"Error executing command: {str(e)}",
            "return_code": -1,
            "success": False
        }


@mcp.tool()
def execute_python(code: str, timeout: int = 300) -> dict:
    """
    Execute Python code and return the output.
    
    Args:
        code: Python code to execute
        timeout: Timeout in seconds (default: 300)
        
    Returns:
        Dictionary with stdout, stderr, success status, and exception info
    """
    import io
    import contextlib
    
    # Capture stdout and stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    
    try:
        with contextlib.redirect_stdout(stdout_capture), contextlib.redirect_stderr(stderr_capture):
            exec(code, {})
        
        return {
            "stdout": stdout_capture.getvalue(),
            "stderr": stderr_capture.getvalue(),
            "success": True,
            "exception_type": None
        }
    except Exception as e:
        return {
            "stdout": stdout_capture.getvalue(),
            "stderr": f"{type(e).__name__}: {str(e)}",
            "success": False,
            "exception_type": type(e).__name__
        }


@mcp.tool()
def web_search(query: str, max_results: int = 10) -> dict:
    """
    Perform a web search using DuckDuckGo.
    
    Args:
        query: Search query string
        max_results: Maximum number of results to return
        
    Returns:
        Dictionary with search results and success status
    """
    try:
        from ddgs import DDGS
        
        results = []
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                results.append({
                    'title': r.get('title'),
                    'href': r.get('href'),
                    'body': r.get('body')
                })
        
        return {
            "results": results,
            "success": True
        }
    except Exception as e:
        return {
            "results": [],
            "success": False,
            "error": str(e)
        }


@mcp.tool()
def crawl_url(url: str, extract_type: str = "markdown") -> dict:
    """
    Crawl a URL and extract content.
    
    Args:
        url: URL to crawl
        extract_type: Type of extraction - 'markdown', 'text', or 'links'
        
    Returns:
        Dictionary with extracted content and success status
    """
    try:
        from crawl4ai import WebCrawler
        
        crawler = WebCrawler()
        crawler.warmup()
        
        result = crawler.run(url)
        
        if result.success:
            if extract_type == "markdown":
                content = result.markdown
            elif extract_type == "text":
                content = result.cleaned_html
            elif extract_type == "links":
                content = str(result.links)
            else:
                content = result.markdown
            
            return {
                "content": content,
                "success": True,
                "error": None
            }
        else:
            return {
                "content": None,
                "success": False,
                "error": result.error_message
            }
    except ImportError:
        return {
            "content": None,
            "success": False,
            "error": "crawl4ai not installed. Install with: pip install crawl4ai"
        }
    except Exception as e:
        return {
            "content": None,
            "success": False,
            "error": str(e)
        }


# ============================================================================
# Server Entry Point
# ============================================================================

if __name__ == "__main__":
    # Run the MCP server via stdio
    mcp.run()
