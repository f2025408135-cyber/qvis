import pytest
from unittest.mock import patch, MagicMock
from backend.collectors.github_scanner import GitHubTokenScanner

@pytest.mark.asyncio
async def test_github_scanner_initialization_with_token():
    scanner = GitHubTokenScanner(token="fake_token")
    assert "Authorization" in scanner.headers
    assert scanner.headers["Authorization"] == "Bearer fake_token"

@pytest.mark.asyncio
async def test_github_scanner_initialization_without_token():
    scanner = GitHubTokenScanner()
    assert "Authorization" not in scanner.headers

@pytest.mark.asyncio
@patch('backend.collectors.github_scanner.httpx.AsyncClient.get')
async def test_github_scanner_search_success(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "items": [
            {
                "repository": {"full_name": "test/repo"},
                "path": "test.py",
                "html_url": "https://github.com/test/repo",
                "text_matches": [{"fragment": "QiskitRuntimeService(token='exposed_token_123')"}]
            }
        ]
    }
    
    # Let AsyncMock return the MagicMock synchronously without async def wrapper
    mock_get.return_value = mock_response
    
    scanner = GitHubTokenScanner(token="fake")
    results = await scanner.search("QiskitRuntimeService")
    
    assert len(results) == 1
    assert results[0]["repo"] == "test/repo"
    assert results[0]["pattern"] == "QiskitRuntimeService(token='exposed_token_123')"

@pytest.mark.asyncio
@patch('backend.collectors.github_scanner.httpx.AsyncClient.get')
async def test_github_scanner_search_rate_limited(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_get.return_value = mock_response
    
    scanner = GitHubTokenScanner(token="fake")
    results = await scanner.search("QiskitRuntimeService")
    
    assert len(results) == 0

@pytest.mark.asyncio
@patch('backend.collectors.github_scanner.httpx.AsyncClient.get')
async def test_github_scanner_search_unauthorized(mock_get):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response
    
    scanner = GitHubTokenScanner(token="fake")
    results = await scanner.search("QiskitRuntimeService")
    
    assert len(results) == 0
