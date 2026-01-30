# src/security/exception_handler.py
import sys
import traceback
from typing import Optional

class SafeExceptionHandler:
    
    def __init__(self, hide_internal_details: bool = True):
        self.hide_internal_details = hide_internal_details
        self.allowed_exceptions = [
            "ValueError", "TypeError", "KeyError", 
            "AttributeError", "SecurityException"
        ]
    
    def safe_execute(self, func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            return self.handle_exception(e, func.__name__)
    
    async def safe_execute_async(self, func, *args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            return self.handle_exception(e, func.__name__)
    
    def handle_exception(self, exception: Exception, context: str = "") -> str:
        exc_type = type(exception).__name__
        
        self._log_exception(exception, context)
        
        if self.hide_internal_details:
            if exc_type in self.allowed_exceptions:
                return f"Ошибка в {context}: {str(exception)}"
            else:
                return f"Произошла внутренняя ошибка при выполнении {context}. Обратитесь к администратору."
        else:
            return str(exception)
    
    def _log_exception(self, exception: Exception, context: str):
        import logging
        logger = logging.getLogger(__name__)
        
        exc_info = (type(exception), exception, exception.__traceback__)
        logger.error(f"Exception in {context}: {exception}", exc_info=exc_info)
        
        with open("security_exceptions.log", "a") as f:
            f.write(f"\n[{self._get_timestamp()}] {context}: {exception}\n")
            if not self.hide_internal_details:
                traceback.print_exc(file=f)
    
    def _get_timestamp(self) -> str:
        from datetime import datetime
        return datetime.now().isoformat()
