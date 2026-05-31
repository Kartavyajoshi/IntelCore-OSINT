# database.py - Database Storage and Management (Enhanced)
import sqlite3
import json
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from config import get_config
from logger import get_logger

logger = get_logger()

class DatabaseManager:
    """Manages SQLite database for scan storage"""
    
    def __init__(self):
        self.config = get_config().database
        self.db_path = self.config.db_path
        self.enabled = self.config.enabled
        
        if self.enabled:
            self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database schema"""
        try:
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL UNIQUE,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    risk_score INTEGER,
                    risk_level TEXT,
                    modules_completed INTEGER,
                    modules_total INTEGER,
                    duration FLOAT,
                    report_file TEXT,
                    dump_file TEXT
                )
            ''')
            
            # Scan results table (detailed data)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    module_name TEXT NOT NULL,
                    data TEXT,
                    status TEXT,
                    error TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    type TEXT,
                    severity TEXT,
                    description TEXT,
                    remediation TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Email breaches table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS email_breaches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    email TEXT,
                    breach_source TEXT,
                    breach_date TEXT,
                    fields_compromised TEXT,
                    risk_level TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            # Crawl results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crawl_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    url TEXT,
                    depth INTEGER,
                    layer TEXT,
                    title TEXT,
                    emails_found INTEGER DEFAULT 0,
                    docs_found INTEGER DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            # Credentials table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    email TEXT,
                    source TEXT,
                    breach_name TEXT,
                    data_types TEXT,
                    has_password INTEGER DEFAULT 0,
                    risk_level TEXT,
                    breach_date TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            # Gov records table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS gov_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    record_type TEXT,
                    entity_name TEXT,
                    source TEXT,
                    data TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')

            # Correlations table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    entity_type TEXT,
                    entity_value TEXT,
                    risk_level TEXT,
                    reason TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            ''')
            
            # Create indexes
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_target ON scans(target)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scans(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_breach_email ON email_breaches(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cred_email ON credentials(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_crawl_layer ON crawl_results(layer)')
            
            conn.commit()
            conn.close()
            logger.info(f"[DB] Initialized database: {self.db_path}")
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to initialize database: {e}")
    
    def save_scan(self, scan_data: Dict[str, Any]) -> Optional[int]:
        """Save scan to database"""
        if not self.enabled:
            return None
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO scans 
                (target, timestamp, status, risk_score, risk_level, 
                 modules_completed, modules_total, report_file, dump_file)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_data.get('target'),
                scan_data.get('timestamp'),
                scan_data.get('scan_status'),
                scan_data.get('risk_score', {}).get('score'),
                scan_data.get('risk_score', {}).get('level'),
                scan_data.get('modules_completed'),
                scan_data.get('modules_total'),
                scan_data.get('report_file'),
                scan_data.get('dump_file')
            ))
            
            conn.commit()
            scan_id = cursor.lastrowid
            
            # Save individual module results
            for module_name, module_data in scan_data.items():
                if module_name not in ['target', 'timestamp', 'scan_status', 'risk_score', 
                                       'modules_completed', 'modules_total', 'report_file',
                                       'dump_file', 'execution_report']:
                    try:
                        cursor.execute('''
                            INSERT INTO scan_results (scan_id, module_name, data, status)
                            VALUES (?, ?, ?, ?)
                        ''', (
                            scan_id,
                            module_name,
                            json.dumps(module_data, default=str),
                            'completed'
                        ))
                    except Exception as e:
                        logger.warning(f"[DB] Failed to save module {module_name}: {e}")
            
            # Save email breaches
            for breach in scan_data.get('breaches', {}).get('results', []):
                try:
                    cursor.execute('''
                        INSERT INTO email_breaches 
                        (scan_id, email, breach_source, breach_date, fields_compromised, risk_level)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        breach.get('email'),
                        ','.join([s.get('name', '') for s in breach.get('sources', breach.get('breaches', []))]),
                        breach.get('most_recent_date', ''),
                        ','.join(breach.get('compromised_fields', breach.get('data_leaked', []))),
                        breach.get('risk_level')
                    ))
                except Exception as e:
                    logger.warning(f"[DB] Failed to save breach: {e}")

            # Save credential intel
            cred_intel = scan_data.get('credential_intel', {})
            if isinstance(cred_intel, dict):
                for entry in cred_intel.get('hibp_emails', []):
                    try:
                        cursor.execute('''
                            INSERT INTO credentials
                            (scan_id, email, source, data_types, has_password, risk_level)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            scan_id,
                            entry.get('email', ''),
                            'HIBP',
                            json.dumps([dt for b in entry.get('breaches', []) for dt in b.get('data_types', [])]),
                            1 if entry.get('has_password_leak') else 0,
                            entry.get('risk_level', 'LOW'),
                        ))
                    except Exception as e:
                        logger.warning(f"[DB] Failed to save credential: {e}")

            # Save correlations
            correlations = scan_data.get('correlations', {})
            if isinstance(correlations, dict):
                for entity in correlations.get('risk_entities', []):
                    try:
                        cursor.execute('''
                            INSERT INTO correlations
                            (scan_id, entity_type, entity_value, risk_level, reason)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (
                            scan_id,
                            entity.get('type', ''),
                            entity.get('value', ''),
                            entity.get('risk', ''),
                            entity.get('reason', ''),
                        ))
                    except Exception as e:
                        logger.warning(f"[DB] Failed to save correlation: {e}")
            
            conn.commit()
            conn.close()
            
            logger.info(f"[DB] Saved scan for {scan_data.get('target')} (ID: {scan_id})")
            return scan_id
        
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to save scan: {e}")
            return None
    
    def get_scan(self, target: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan from database"""
        if not self.enabled:
            return None
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM scans WHERE target = ?', (target,))
            row = cursor.fetchone()
            
            if row:
                columns = [description[0] for description in cursor.description]
                scan = dict(zip(columns, row))
                
                # Get associated results
                cursor.execute('SELECT module_name, data FROM scan_results WHERE scan_id = ?', 
                              (scan['id'],))
                scan['modules'] = {row[0]: json.loads(row[1]) for row in cursor.fetchall()}
                
                conn.close()
                return scan
            
            conn.close()
            return None
        
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to retrieve scan: {e}")
            return None
    
    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent scans"""
        if not self.enabled:
            return []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM scans 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = [description[0] for description in cursor.description]
            scans = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return scans
        
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to retrieve recent scans: {e}")
            return []
    
    def get_breach_emails(self, target: str = None) -> List[Dict[str, Any]]:
        """Get compromised emails"""
        if not self.enabled:
            return []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if target:
                cursor.execute('''
                    SELECT eb.* FROM email_breaches eb
                    JOIN scans s ON eb.scan_id = s.id
                    WHERE s.target = ?
                    ORDER BY eb.id DESC
                ''', (target,))
            else:
                cursor.execute('''
                    SELECT * FROM email_breaches 
                    ORDER BY id DESC
                ''')
            
            columns = [description[0] for description in cursor.description]
            breaches = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return breaches
        
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to retrieve breaches: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        if not self.enabled:
            return {}
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM scans')
            total_scans = cursor.fetchone()[0]
            
            cursor.execute('SELECT AVG(risk_score) FROM scans WHERE risk_score IS NOT NULL')
            avg_risk = cursor.fetchone()[0] or 0
            
            cursor.execute('SELECT risk_level, COUNT(*) FROM scans GROUP BY risk_level')
            risk_distribution = dict(cursor.fetchall())
            
            cursor.execute('SELECT COUNT(DISTINCT email) FROM email_breaches')
            unique_breached_emails = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM credentials WHERE has_password = 1')
            password_leaks = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM crawl_results')
            crawled_pages = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_scans': total_scans,
                'average_risk_score': round(avg_risk, 1),
                'risk_distribution': risk_distribution,
                'unique_breached_emails': unique_breached_emails,
                'password_leaks_found': password_leaks,
                'total_crawled_pages': crawled_pages,
            }
        
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to get statistics: {e}")
            return {}
    
    def clear_old_scans(self, days: int = 90):
        """Clear scans older than specified days"""
        if not self.enabled:
            return
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM scans 
                WHERE datetime(timestamp) < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"[DB] Cleared scans older than {days} days")
        
        except Exception as e:
            logger.error(f"[DB ERROR] Failed to clear old scans: {e}")

# Global database instance
_db_manager = None

def get_database() -> DatabaseManager:
    """Get global database instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
