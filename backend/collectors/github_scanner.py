"""Collector for scanning GitHub for exposed IBM Quantum API tokens."""

import httpx
import structlog
from typing import Optional, List, Dict, Any

logger = structlog.get_logger()

class GitHubTokenScanner:
    """Scans GitHub for exposed IBM Quantum tokens using GitHub's code search API."""

    def __init__(self, token: Optional[str] = None):
        """Initializes the scanner with an optional GitHub Personal Access Token.
        
        Args:
            token: GitHub PAT with 'repo' scope.
        """
        self.token = token
        self.headers = {
            "Accept": "application/vnd.github.v3.text-match+json",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    async def search(self, query: str) -> List[Dict[str, Any]]:
        """Search GitHub code for a pattern.
        
        Args:
            query: The GitHub code search query string.
            
        Returns:
            List of matching result dictionaries.
        """
        from urllib.parse import quote as _url_quote
        url = f"https://api.github.com/search/code?q={_url_quote(query)}"
        results = []
        
        try:
            async with httpx.AsyncClient(headers=self.headers, timeout=10.0) as client:
                response = await client.get(url)
                
                if response.status_code == 403:
                    logger.warning("github_search_rate_limited", url=url)
                    return []
                elif response.status_code == 401:
                    logger.warning("github_search_unauthorized", url=url)
                    return []
                    
                response.raise_for_status()
                data = response.json()
                
                for item in data.get("items", []):
                    repo_name = item.get("repository", {}).get("full_name", "unknown")
                    file_path = item.get("path", "unknown")
                    
                    # Extract the matched text if available;
                    # only include it when GitHub actually returned a
                    # text fragment — never fabricate a placeholder.
                    match_text = None
                    text_matches = item.get("text_matches", [])
                    if text_matches:
                        match_text = text_matches[0].get("fragment", None)

                    if not match_text:
                        # Skip entries without a visible match — they
                        # are not useful as threat evidence.
                        continue
                    
                    results.append({
                        "repo": repo_name,
                        "file": file_path,
                        "pattern": match_text,
                        "url": item.get("html_url", "")
                    })
                    
        except Exception as e:
            logger.error("github_search_failed", query=query, error=str(e))
            
        return results

    async def scan_for_ibm_tokens(self) -> List[Dict[str, Any]]:
        """Search for exposed IBM Quantum API tokens on GitHub.
        
        Returns:
            List of structured match dictionaries feeding into Threat Engine Rule 001.
        """
        # A realistic search query for exposed IBM Qiskit tokens
        query = "QiskitRuntimeService+token+"
        return await self.search(query)
