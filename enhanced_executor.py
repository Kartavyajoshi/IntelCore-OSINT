# enhanced_executor.py - Robust Parallel Execution Engine
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from typing import Dict, Callable, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
from logger import get_logger

logger = get_logger()

class ModuleStatus(Enum):
    """Module execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"

@dataclass
class ModuleResult:
    """Result of module execution"""
    name: str
    status: ModuleStatus
    data: Optional[Any] = None
    error: Optional[str] = None
    duration: float = 0.0
    attempt: int = 1
    
    def to_dict(self):
        return {
            'name': self.name,
            'status': self.status.value,
            'error': self.error,
            'duration': round(self.duration, 2),
            'attempt': self.attempt,
            'success': self.status == ModuleStatus.COMPLETED
        }

class EnhancedExecutor:
    """Enhanced parallel executor with progress tracking"""
    
    def __init__(self, max_workers: int = 8, timeout_per_module: int = 60):
        self.max_workers = max_workers
        self.timeout_per_module = timeout_per_module
        self.results: Dict[str, ModuleResult] = {}
        self.lock = threading.Lock()
        self.start_time = None
        self.total_duration = 0
    
    def execute_modules(self,
                       modules: Dict[str, Callable],
                       args: tuple = (),
                       kwargs: dict = None,
                       retry_count: int = 2) -> Dict[str, ModuleResult]:
        """
        Execute multiple modules in parallel with timeout and retry
        
        Args:
            modules: Dict of {module_name: callable}
            args: Positional arguments for all modules
            kwargs: Keyword arguments for all modules
            retry_count: Number of retry attempts on failure
        
        Returns:
            Dict of {module_name: ModuleResult}
        """
        self.start_time = time.time()
        self.results = {}
        kwargs = kwargs or {}
        
        logger.info(f"[EXECUTOR] Starting {len(modules)} modules (max {self.max_workers} workers)")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Create initial futures
            futures = {}
            for module_name, module_func in modules.items():
                future = executor.submit(
                    self._execute_with_timeout,
                    module_name,
                    module_func,
                    args,
                    kwargs,
                    retry_count
                )
                futures[future] = module_name
            
            # Process completed futures
            completed_count = 0
            total_modules = len(modules)
            
            for future in as_completed(futures):
                module_name = futures[future]
                completed_count += 1
                
                try:
                    result = future.result()
                    self.results[module_name] = result
                    
                    status_icon = "OK" if result.status == ModuleStatus.COMPLETED else "FAIL"
                    logger.info(
                        f"[{status_icon}] {module_name}: {result.status.value} "
                        f"({result.duration:.1f}s) [{completed_count}/{total_modules}]"
                    )
                    
                except Exception as e:
                    logger.error(f"[ERROR] {module_name}: {e}")
                    self.results[module_name] = ModuleResult(
                        name=module_name,
                        status=ModuleStatus.FAILED,
                        error=str(e)
                    )
        
        self.total_duration = time.time() - self.start_time
        self._print_summary()
        
        return self.results
    
    def _execute_with_timeout(self,
                             module_name: str,
                             module_func: Callable,
                             args: tuple,
                             kwargs: dict,
                             max_retries: int) -> ModuleResult:
        """Execute module with timeout and retry logic"""
        
        for attempt in range(1, max_retries + 1):
            try:
                start_time = time.time()
                
                logger.debug(f"[RUN] {module_name} (attempt {attempt}/{max_retries})")
                
                # Execute with timeout
                result_data = self._run_with_timeout(
                    module_func,
                    args,
                    kwargs,
                    self.timeout_per_module
                )
                
                duration = time.time() - start_time
                
                return ModuleResult(
                    name=module_name,
                    status=ModuleStatus.COMPLETED,
                    data=result_data,
                    duration=duration,
                    attempt=attempt
                )
            
            except TimeoutError:
                logger.warning(f"[TIMEOUT] {module_name} (attempt {attempt}/{max_retries})")
                
                if attempt == max_retries:
                    return ModuleResult(
                        name=module_name,
                        status=ModuleStatus.TIMEOUT,
                        error=f"Module timeout after {self.timeout_per_module}s",
                        attempt=attempt
                    )
            
            except Exception as e:
                logger.error(f"[ERROR] {module_name}: {e} (attempt {attempt}/{max_retries})")
                
                if attempt == max_retries:
                    return ModuleResult(
                        name=module_name,
                        status=ModuleStatus.FAILED,
                        error=str(e),
                        attempt=attempt
                    )
                
                # Wait before retry
                time.sleep(2 ** attempt)
        
        return ModuleResult(
            name=module_name,
            status=ModuleStatus.FAILED,
            error="All retry attempts failed"
        )
    
    @staticmethod
    def _run_with_timeout(func: Callable, args: tuple, kwargs: dict, timeout: float) -> Any:
        """Run function with timeout using thread"""
        import threading
        
        result = [None]
        exception = [None]
        
        def target():
            try:
                result[0] = func(*args, **kwargs)
            except Exception as e:
                exception[0] = e
        
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(timeout=timeout)
        
        if thread.is_alive():
            raise TimeoutError(f"Function timed out after {timeout}s")
        
        if exception[0]:
            raise exception[0]
        
        return result[0]
    
    def get_results(self) -> Dict[str, Any]:
        """Get execution results"""
        return {
            name: result.data
            for name, result in self.results.items()
            if result.status == ModuleStatus.COMPLETED
        }
    
    def get_status_report(self) -> Dict[str, Any]:
        """Get detailed status report"""
        status_counts = {}
        for result in self.results.values():
            status = result.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            'total_modules': len(self.results),
            'total_duration': round(self.total_duration, 2),
            'status_summary': status_counts,
            'modules': [result.to_dict() for result in self.results.values()]
        }
    
    def _print_summary(self):
        """Print execution summary"""
        logger.info(f"\n{'='*70}")
        logger.info(f"[SUMMARY] Execution completed in {self.total_duration:.1f}s")
        
        status_counts = {}
        for result in self.results.values():
            status = result.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        for status, count in status_counts.items():
            logger.info(f"  {status.upper()}: {count}")
        
        logger.info(f"{'='*70}\n")

def execute_parallel_modules(modules: Dict[str, Callable],
                            args: tuple = (),
                            kwargs: dict = None,
                            max_workers: int = 8,
                            timeout_per_module: int = 60,
                            retry_count: int = 2) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Convenience function for parallel execution
    
    Returns:
        Tuple of (results, status_report)
    """
    executor = EnhancedExecutor(max_workers, timeout_per_module)
    module_results = executor.execute_modules(
        modules,
        args,
        kwargs,
        retry_count
    )
    
    return executor.get_results(), executor.get_status_report()
