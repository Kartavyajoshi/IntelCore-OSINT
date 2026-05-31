# cache_manager.py - Intelligent Caching System
import os
import json
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Optional
import pickle
from config import get_config
from logger import get_logger

logger = get_logger()

class CacheManager:
    """Manages result caching with TTL"""
    
    def __init__(self):
        self.config = get_config().cache
        self.cache_dir = Path(self.config.cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.enabled = self.config.enabled
    
    def _get_cache_key(self, module: str, target: str, params: dict = None) -> str:
        """Generate cache key from module, target, and params"""
        key_str = f"{module}:{target}:{json.dumps(params or {}, sort_keys=True)}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_file(self, cache_key: str) -> Path:
        """Get cache file path"""
        return self.cache_dir / f"{cache_key}.cache"
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid (not expired)"""
        if not cache_file.exists():
            return False
        
        file_age = time.time() - cache_file.stat().st_mtime
        ttl_seconds = self.config.ttl_hours * 3600
        
        return file_age < ttl_seconds
    
    def get(self, module: str, target: str, params: dict = None) -> Optional[Any]:
        """Retrieve cached result if valid"""
        if not self.enabled:
            return None
        
        try:
            cache_key = self._get_cache_key(module, target, params)
            cache_file = self._get_cache_file(cache_key)
            
            if self._is_cache_valid(cache_file):
                with open(cache_file, 'rb') as f:
                    result = pickle.load(f)
                    logger.debug(f"[CACHE HIT] {module} for {target}")
                    return result
            elif cache_file.exists():
                cache_file.unlink()
                logger.debug(f"[CACHE EXPIRED] {module} for {target}")
        except Exception as e:
            logger.warning(f"[CACHE ERROR] Failed to retrieve cache: {e}")
        
        return None
    
    def set(self, module: str, target: str, data: Any, params: dict = None):
        """Cache result"""
        if not self.enabled:
            return
        
        try:
            cache_key = self._get_cache_key(module, target, params)
            cache_file = self._get_cache_file(cache_key)
            
            with open(cache_file, 'wb') as f:
                pickle.dump(data, f)
            
            logger.debug(f"[CACHE SET] {module} for {target}")
            self._cleanup_old_cache()
        except Exception as e:
            logger.warning(f"[CACHE ERROR] Failed to cache result: {e}")
    
    def _cleanup_old_cache(self):
        """Remove old cache files if cache size exceeds limit"""
        try:
            max_size_bytes = self.config.max_cache_size_mb * 1024 * 1024
            
            # Calculate current cache size
            cache_size = sum(f.stat().st_size for f in self.cache_dir.glob('*.cache'))
            
            if cache_size > max_size_bytes:
                # Remove oldest files
                cache_files = sorted(
                    self.cache_dir.glob('*.cache'),
                    key=lambda f: f.stat().st_mtime)
                
                for cache_file in cache_files:
                    if cache_size <= max_size_bytes:
                        break
                    cache_size -= cache_file.stat().st_size
                    cache_file.unlink()
                    logger.debug(f"[CACHE CLEANUP] Removed {cache_file.name}")
        except Exception as e:
            logger.warning(f"[CACHE CLEANUP ERROR] {e}")
    
    def clear(self, module: str = None, target: str = None):
        """Clear cache for specific module/target or all"""
        try:
            if module is None and target is None:
                # Clear all
                for cache_file in self.cache_dir.glob('*.cache'):
                    cache_file.unlink()
                logger.info("[CACHE] Cleared all cache")
            else:
                # Clear specific
                for cache_file in self.cache_dir.glob('*.cache'):
                    cache_file.unlink()
                logger.info(f"[CACHE] Cleared cache for {module}:{target}")
        except Exception as e:
            logger.warning(f"[CACHE CLEAR ERROR] {e}")
    
    def get_stats(self) -> dict:
        """Get cache statistics"""
        try:
            cache_files = list(self.cache_dir.glob('*.cache'))
            total_size = sum(f.stat().st_size for f in cache_files)
            
            return {
                'cache_files': len(cache_files),
                'total_size_mb': round(total_size / (1024 * 1024), 2),
                'ttl_hours': self.config.ttl_hours,
                'cache_dir': str(self.cache_dir)
            }
        except Exception as e:
            logger.warning(f"[CACHE STATS ERROR] {e}")
            return {}

# Global cache instance
_cache_manager = None

def get_cache_manager() -> CacheManager:
    """Get global cache manager instance"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager
