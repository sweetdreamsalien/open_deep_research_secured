# src/security/circuit_breaker.py
import time
from typing import Dict
from dataclasses import dataclass, field

class CircuitBreakerException(Exception):
    pass

@dataclass
class ResearchCircuit:
    iteration_count: int = 0
    max_iterations: int = 5
    last_iteration_time: float = field(default_factory=time.time)
    
    def can_iterate(self) -> bool:
        if self.iteration_count >= self.max_iterations:
            return False
        elapsed = time.time() - self.last_iteration_time
        if elapsed < 1.0:
            return False
        return True
    
    def register_iteration(self):
        self.iteration_count += 1
        self.last_iteration_time = time.time()

class ResearchCircuitBreaker:
    _instance = None
    _circuits: Dict[str, ResearchCircuit] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def get_circuit_id(self, topic: str, section_name: str) -> str:
        import hashlib
        key = f"{topic}_{section_name}"
        return hashlib.md5(key.encode()).hexdigest()[:12]
    
    def check_and_register(self, circuit_id: str, max_iterations: int = 5) -> bool:
        if circuit_id not in self._circuits:
            self._circuits[circuit_id] = ResearchCircuit(max_iterations=max_iterations)
        
        circuit = self._circuits[circuit_id]
        
        if not circuit.can_iterate():
            raise CircuitBreakerException(
                f"Превышен лимит итераций: {circuit.iteration_count}/{circuit.max_iterations}"
            )
        
        circuit.register_iteration()
        return True
    
    def reset_circuit(self, circuit_id: str):
        if circuit_id in self._circuits:
            del self._circuits[circuit_id]
