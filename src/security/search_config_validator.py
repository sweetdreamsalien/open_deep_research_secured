# src/security/search_config_validator.py
import re
from typing import Dict, Any, Optional

class SearchConfigValidator:
    
    SAFE_SEARCH_PARAMS = {
        "tavily": ["max_results", "include_domains", "exclude_domains", "timeout"],
        "duckduckgo": ["max_results", "timeout"],
        "perplexity": ["max_results", "timeout"],
        "exa": ["max_results", "include_domains", "timeout"],
        "arxiv": ["max_results", "sort_by"],
        "pubmed": ["max_results", "retmax"]
    }
    
    PARAM_LIMITS = {
        "max_results": (1, 50),
        "timeout": (1, 30),
        "retmax": (1, 100)
    }
    
    FORBIDDEN_DOMAINS = [".internal", ".local", "sharepoint.", "confluence.", "intranet."]
    
    def validate(self, search_api: str, config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        if not config:
            return {}
        
        safe_config = {}
        api = search_api.lower()
        
        allowed_params = self.SAFE_SEARCH_PARAMS.get(api, [])
        
        for param, value in config.items():
            if param not in allowed_params:
                continue
            
            if param in self.PARAM_LIMITS:
                min_val, max_val = self.PARAM_LIMITS[param]
                if isinstance(value, (int, float)):
                    if value < min_val or value > max_val:
                        value = max(min_val, min(value, max_val))
            
            if param == "include_domains":
                value = self._validate_domains(value)
            
            safe_config[param] = value
        
        return safe_config
    
    def _validate_domains(self, domains) -> list:
        if not domains:
            return []
        
        safe_domains = []
        for domain in domains:
            domain_lower = domain.lower()
            if not any(forbidden in domain_lower for forbidden in self.FORBIDDEN_DOMAINS):
                safe_domains.append(domain)
        
        return safe_domains
