"""
Wayback Machine / Archive.org OSINT Module
Historical website snapshots, content changes, removed files discovery
Free API - no authentication required
"""

import requests
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any
from urllib.parse import urlparse
import time

def wayback_machine_analyzer(target: str) -> Dict[str, Any]:
    """
    Analyze website history via Wayback Machine (archive.org)
    
    Args:
        target: Domain or URL to analyze
    
    Returns:
        Dict with historical snapshots, timeline, and changes
    """
    print(f"[*] Analyzing Wayback Machine history for: {target}")
    
    try:
        # Normalize target
        target = target.strip().lower()
        if not target.startswith('http'):
            target = f'https://{target}'
        
        results = {
            'status': 'success',
            'target': target,
            'timeline': {},
            'snapshots': [],
            'changes': {},
            'intelligence': {},
            'timestamp': time.time()
        }
        
        # 1. Get available snapshots
        snapshots = _get_snapshots(target)
        results['snapshots'] = snapshots
        
        # 2. Analyze timeline
        if snapshots:
            results['timeline'] = _analyze_timeline(snapshots)
            results['intelligence']['total_captures'] = len(snapshots)
            results['intelligence']['first_capture'] = snapshots[0].get('date') if snapshots else None
            results['intelligence']['latest_capture'] = snapshots[-1].get('date') if snapshots else None
            
            # 3. Detect changes
            results['changes'] = _detect_changes(snapshots[:10])  # Check last 10 snapshots
        
        # 4. Get URLs discovered through Wayback
        results['discovered_urls'] = _get_discovered_urls(target)
        
        # 5. Search for removed content
        results['removed_content'] = _detect_removed_content(target, snapshots)
        
        # 6. Technology fingerprinting from old snapshots
        results['historical_tech'] = _get_historical_tech(target)
        
        print(f"[+] Wayback analysis complete: {len(snapshots)} snapshots found")
        return results
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'Wayback Machine analysis failed: {str(e)}',
            'error': str(e)
        }

def _get_snapshots(url: str, limit: int = 100) -> List[Dict[str, Any]]:
    """Fetch available snapshots from Wayback Machine"""
    try:
        # Parse URL for archive.org API
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        
        # Use Wayback Machine CDX API
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': domain + '*',
            'output': 'json',
            'collapse': 'statuscode',
            'matchType': 'prefix',
            'sort': 'timestamp',
            'limit': limit,
            'filter': '=statuscode:200'
        }
        
        response = requests.get(cdx_url, params=params, timeout=20)
        response.raise_for_status()
        
        data = response.json()
        
        # Parse results (first row is headers)
        if len(data) <= 1:
            return []
        
        snapshots = []
        for record in data[1:]:
            # record format: [url, timestamp, original, statuscode, length]
            if len(record) >= 2:
                snapshots.append({
                    'url': record[0],
                    'timestamp': record[1],
                    'date': _format_timestamp(record[1]),
                    'status': record[3] if len(record) > 3 else 'unknown',
                    'archive_url': f"https://web.archive.org/web/{record[1]}/{record[0]}"
                })
        
        return sorted(snapshots, key=lambda x: x['timestamp'])
        
    except Exception as e:
        print(f"[!] Error fetching snapshots: {e}")
        return []

def _analyze_timeline(snapshots: List[Dict]) -> Dict[str, Any]:
    """Analyze snapshot distribution over time"""
    timeline = {
        'by_year': {},
        'by_month': {},
        'capture_frequency': 'unknown'
    }
    
    try:
        for snapshot in snapshots:
            date_str = snapshot.get('date', '')
            if date_str:
                year = date_str[:4]
                month = date_str[:7]
                
                timeline['by_year'][year] = timeline['by_year'].get(year, 0) + 1
                timeline['by_month'][month] = timeline['by_month'].get(month, 0) + 1
        
        # Determine capture frequency
        if timeline['by_year']:
            avg_per_year = len(snapshots) / len(timeline['by_year'])
            if avg_per_year > 50:
                timeline['capture_frequency'] = 'very_frequent (50+ per year)'
            elif avg_per_year > 10:
                timeline['capture_frequency'] = 'frequent (10-50 per year)'
            else:
                timeline['capture_frequency'] = 'occasional (< 10 per year)'
    except:
        pass
    
    return timeline

def _detect_changes(recent_snapshots: List[Dict]) -> Dict[str, Any]:
    """Detect changes between recent snapshots"""
    changes = {
        'detected': False,
        'details': []
    }
    
    try:
        if len(recent_snapshots) < 2:
            return changes
        
        # Compare most recent snapshots
        for i in range(len(recent_snapshots) - 1):
            if recent_snapshots[i]['timestamp'] != recent_snapshots[i+1]['timestamp']:
                changes['detected'] = True
                changes['details'].append({
                    'from': recent_snapshots[i]['date'],
                    'to': recent_snapshots[i+1]['date'],
                    'days_apart': _days_between_timestamps(
                        recent_snapshots[i]['timestamp'],
                        recent_snapshots[i+1]['timestamp']
                    )
                })
    except:
        pass
    
    return changes

def _get_discovered_urls(target: str) -> Dict[str, Any]:
    """Get URLs discovered through Wayback Machine"""
    try:
        parsed = urlparse(target)
        domain = parsed.netloc.replace('www.', '')
        
        # Use Wayback CDX to discover URLs
        cdx_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            'url': domain + '*',
            'output': 'json',
            'collapse': 'urlkey',
            'limit': 50,
            'filter': '=statuscode:200'
        }
        
        response = requests.get(cdx_url, params=params, timeout=20)
        data = response.json()
        
        urls = []
        for record in data[1:]:  # Skip headers
            urls.append(record[0])
        
        return {
            'discovered_count': len(urls),
            'sample_urls': urls[:20],
            'total_archived': len(urls)
        }
    except:
        return {'discovered_count': 0, 'sample_urls': []}

def _detect_removed_content(target: str, snapshots: List[Dict]) -> Dict[str, Any]:
    """Detect content that was removed (404s)"""
    removed = {
        'potentially_removed': False,
        'indicators': []
    }
    
    try:
        # Count 404 responses if available in snapshots
        error_count = sum(1 for s in snapshots if s.get('status') == '404')
        if error_count > len(snapshots) * 0.3:  # More than 30% errors
            removed['potentially_removed'] = True
            removed['indicators'].append(f'{error_count} 404 responses found')
    except:
        pass
    
    return removed

def _get_historical_tech(target: str) -> Dict[str, Any]:
    """Detect technology stack from historical snapshots"""
    try:
        parsed = urlparse(target)
        domain = parsed.netloc.replace('www.', '')
        
        tech_indicators = {
            'frameworks': [],
            'platforms': [],
            'indicators': []
        }
        
        # Check for common tech in various snapshots
        snapshot_samples = [
            '202301',  # Jan 2023
            '202201',  # Jan 2022
            '202101',  # Jan 2021
            '202001',  # Jan 2020
        ]
        
        for snapshot_date in snapshot_samples:
            try:
                archive_url = f"https://web.archive.org/web/{snapshot_date}000000*/{target}"
                response = requests.head(archive_url, timeout=10)
                
                # Check for server headers
                if 'Server' in response.headers:
                    server = response.headers['Server']
                    if 'Apache' in server:
                        tech_indicators['platforms'].append(f'Apache ({snapshot_date})')
                    elif 'nginx' in server:
                        tech_indicators['platforms'].append(f'nginx ({snapshot_date})')
            except:
                pass
        
        return tech_indicators
        
    except:
        return {'frameworks': [], 'platforms': [], 'indicators': []}

def _format_timestamp(timestamp: str) -> str:
    """Format Wayback Machine timestamp to readable date"""
    try:
        if len(timestamp) >= 8:
            year = timestamp[0:4]
            month = timestamp[4:6]
            day = timestamp[6:8]
            return f"{year}-{month}-{day}"
    except:
        pass
    return timestamp

def _days_between_timestamps(ts1: str, ts2: str) -> int:
    """Calculate days between two timestamps"""
    try:
        dt1 = datetime.strptime(ts1[:8], '%Y%m%d')
        dt2 = datetime.strptime(ts2[:8], '%Y%m%d')
        return abs((dt2 - dt1).days)
    except:
        return 0
