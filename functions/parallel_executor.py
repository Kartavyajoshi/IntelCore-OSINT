# functions/parallel_executor.py

from concurrent.futures import ThreadPoolExecutor, as_completed

def execute_modules_parallel(domain, modules_config):
    """Execute multiple modules in parallel"""
    results = {}
    
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(module_func, domain): name 
            for name, module_func in modules_config.items()
        }
        
        for future in as_completed(futures):
            module_name = futures[future]
            try:
                results[module_name] = future.result(timeout=30)
            except Exception as e:
                results[module_name] = {'error': str(e)}
    
    return results