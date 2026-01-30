# src/security/report_structure_validator.py
import json
import re
from typing import Any, Dict, Union

class ReportStructureValidator:
    
    MAX_STRUCTURE_LENGTH = 5000
    ALLOWED_KEYS = ["sections", "introduction", "conclusion", "tables", "lists"]
    
    def __init__(self):
        self.forbidden_patterns = [
            r"__.*__",  # Магические методы
            r"eval\(", r"exec\(", r"compile\(",  # Опасные функции
            r"import\s+os", r"import\s+sys", r"import\s+subprocess",
            r"open\(", r"file\(",  # Файловые операции
            r"subprocess\.", r"os\.system",  # Системные вызовы
            r"confidential|secret|internal",  # Конфиденциальные термины
            r"ACQ-\d{4}", r"M&A", r"стратеги",  # Консалтинговые термины
        ]
    
    def validate(self, report_structure: Union[str, Dict, Any]) -> str:
        if isinstance(report_structure, dict):
            return self._validate_dict_structure(report_structure)
        elif isinstance(report_structure, str):
            return self._validate_string_structure(report_structure)
        else:
            return str(report_structure)
    
    def _validate_dict_structure(self, structure: Dict) -> str:
        safe_dict = {}
        
        for key, value in structure.items():
            if key in self.ALLOWED_KEYS:
                if isinstance(value, (str, int, float, list, dict)):
                    safe_value = self._sanitize_value(value)
                    safe_dict[key] = safe_value
        
        return json.dumps(safe_dict, ensure_ascii=False)
    
    def _validate_string_structure(self, structure: str) -> str:
        if len(structure) > self.MAX_STRUCTURE_LENGTH:
            structure = structure[:self.MAX_STRUCTURE_LENGTH]
        
        for pattern in self.forbidden_patterns:
            if re.search(pattern, structure, re.IGNORECASE):
                structure = re.sub(pattern, "[REMOVED]", structure, flags=re.IGNORECASE)
        
        structure = structure.replace("{", "{{").replace("}", "}}")
        
        return structure
    
    def _sanitize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            for pattern in self.forbidden_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    value = "[SANITIZED]"
                    break
        elif isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        elif isinstance(value, dict):
            return {k: self._sanitize_value(v) for k, v in value.items()}
        
        return value
    
    def is_valid_for_consulting(self, structure: str) -> bool:
        consulting_keywords = [
            "рынок", "анализ", "отчет", "раздел",
            "введение", "заключение", "рекомендации"
        ]
        
        structure_lower = structure.lower()
        return any(keyword in structure_lower for keyword in consulting_keywords)
