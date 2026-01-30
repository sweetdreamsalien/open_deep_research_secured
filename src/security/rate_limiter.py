# src/security/rate_limiter.py
"""Rate limiter для защиты от DoS атак через поисковые запросы"""

import time
from typing import Optional, Dict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

class SecurityException(Exception):
    """Исключение безопасности"""
    pass

@dataclass
class RateLimitConfig:
    """Конфигурация лимитов для консалтинговой компании"""
    max_queries_per_hour: int = 100
    max_queries_per_research: int = 20
    max_concurrent_researches: int = 5
    cost_limit_usd: float = 50.0
    
@dataclass
class ResearchTracker:
    """Трекер ресурсов для одного исследования"""
    research_id: str
    query_count: int = 0
    start_time: float = field(default_factory=time.time)
    total_cost_usd: float = 0.0
    last_query_time: float = field(default_factory=time.time)
    
class ConsultingRateLimiter:
    """Rate limiter для защиты от DoS в консалтинговом контексте"""
    
    _instance = None
    _trackers: Dict[str, ResearchTracker] = {}
    _hourly_queries: Dict[str, int] = {}  # user_id -> query count
    _hourly_reset: float = time.time()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.config = RateLimitConfig()
        return cls._instance
    
    def _get_research_id(self, topic: str) -> str:
        """Генерирует ID исследования на основе темы"""
        import hashlib
        return hashlib.md5(topic.encode()).hexdigest()[:8]
    
    def check_limit(self, topic: Optional[str] = None, 
                   estimated_cost: float = 0.05) -> bool:
        """Проверяет лимиты для исследования"""
        
        # Сбрасываем часовой счетчик если прошёл час
        if time.time() - self._hourly_reset > 3600:
            self._hourly_queries.clear()
            self._hourly_reset = time.time()
        
        if topic:
            research_id = self._get_research_id(topic)
            
            # Инициализируем трекер если нет
            if research_id not in self._trackers:
                self._trackers[research_id] = ResearchTracker(research_id)
            
            tracker = self._trackers[research_id]
            
            # Проверяем лимиты
            # 1. Лимит на исследование
            if tracker.query_count >= self.config.max_queries_per_research:
                raise SecurityException(
                    f"Превышен лимит запросов на исследование: "
                    f"{tracker.query_count}/{self.config.max_queries_per_research}"
                )
            
            # 2. Лимит по времени (макс 10 минут на исследование)
            elapsed_minutes = (time.time() - tracker.start_time) / 60
            if elapsed_minutes > 10:  # 10 минут максимум
                raise SecurityException(
                    f"Превышено время исследования: {elapsed_minutes:.1f}/10 минут"
                )
            
            # 3. Лимит по стоимости
            if tracker.total_cost_usd + estimated_cost > self.config.cost_limit_usd:
                raise SecurityException(
                    f"Превышен лимит стоимости: "
                    f"${tracker.total_cost_usd:.2f}/${self.config.cost_limit_usd:.2f}"
                )
            
            # 4. Обновляем счетчики
            tracker.query_count += 1
            tracker.total_cost_usd += estimated_cost
            tracker.last_query_time = time.time()
        
        # 5. Глобальный часовой лимит (симуляция по IP/user)
        client_id = "default"  # В реальности нужно определять по IP/пользователю
        self._hourly_queries[client_id] = self._hourly_queries.get(client_id, 0) + 1
        
        if self._hourly_queries[client_id] > self.config.max_queries_per_hour:
            raise SecurityException(
                f"Превышен часовой лимит запросов: "
                f"{self._hourly_queries[client_id]}/{self.config.max_queries_per_hour}"
            )
        
        return True
    
    def get_stats(self, topic: Optional[str] = None) -> Dict:
        """Возвращает статистику по лимитам"""
        stats = {
            "hourly_queries": sum(self._hourly_queries.values()),
            "active_researches": len(self._trackers),
            "config": {
                "max_queries_per_research": self.config.max_queries_per_research,
                "max_queries_per_hour": self.config.max_queries_per_hour,
                "cost_limit_usd": self.config.cost_limit_usd
            }
        }
        
        if topic:
            research_id = self._get_research_id(topic)
            if research_id in self._trackers:
                tracker = self._trackers[research_id]
                stats["research"] = {
                    "query_count": tracker.query_count,
                    "elapsed_minutes": (time.time() - tracker.start_time) / 60,
                    "total_cost_usd": tracker.total_cost_usd
                }
        
        return stats
