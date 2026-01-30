# src/security/feedback_validator.py
"""Валидатор обратной связи для консалтинговой компании"""

import re
from typing import Tuple

class FeedbackValidator:
    """Проверяет пользовательский feedback на безопасность"""
    
    def __init__(self):
        # Паттерны атак для консалтингового контекста
        self.forbidden_patterns = [
            r"игнорируй.*инструкц",
            r"забудь.*правила", 
            r"секрет|confidential|internal",
            r"клиент.*данные|client.*data",
            r"проект.*ACQ|M&A.*стратег",
            r"финанс.*модел|financial.*model",
            r"сделай.*иначе|do.*differently",
            r"выведи.*данные|output.*data",
            r"добавь.*в.*отчет|add.*to.*report"
        ]
        
        # Максимальная длина feedback
        self.max_length = 500
        
    def validate(self, feedback: str) -> Tuple[str, bool, str]:
        """Валидирует feedback пользователя"""
        
        # Проверка длины
        if len(feedback) > self.max_length:
            return feedback[:self.max_length], True, "Сокращено до максимальной длины"
        
        # Проверка на инъекции
        for pattern in self.forbidden_patterns:
            if re.search(pattern, feedback, re.IGNORECASE):
                return "[Feedback заблокирован системой безопасности]", True, f"Обнаружен опасный паттерн: {pattern}"
        
        # Экранирование специальных символов
        safe_feedback = feedback.replace('{', '{{').replace('}', '}}')
        
        return safe_feedback, False, "OK"
    
    def is_educational_context(self, feedback: str) -> bool:
        """Определяет, является ли feedback образовательным запросом"""
        educational_keywords = [
            "как работает", "объясни", "пример", "техника",
            "метод", "подход", "best practice", "как защитить"
        ]
        
        feedback_lower = feedback.lower()
        return any(keyword in feedback_lower for keyword in educational_keywords)
