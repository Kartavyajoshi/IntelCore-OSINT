import requests
from bs4 import BeautifulSoup
import json
import os
from urllib.parse import urlparse, urljoin


def fetch_page(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        return response.text
    except Exception as e:
        return None


def extract_links(base_url, html):
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('http'):
            links.add(href)
        else:
            links.add(urljoin(base_url, href))
    return links


def crawl(url, depth=2):
    visited = set()
    to_visit = [(url, 0)]
    results = []
    while to_visit:
        current_url, current_depth = to_visit.pop(0)
        if current_url in visited or current_depth > depth:
            continue
        visited.add(current_url)
        html = fetch_page(current_url)
        if not html:
            continue
        links = extract_links(current_url, html)
        results.append({'url': current_url, 'links': list(links)})
        for link in links:
            to_visit.append((link, current_depth + 1))
    return results

# Simple wrapper for orchestrator
def run_crawler(target, depth=2):
    """Run a basic web crawler for the target domain."""
    base = f"http://{target}" if not target.startswith('http') else target
    return crawl(base, depth)

# Compatibility wrapper expected by orchestrator
def run_full_crawl(target, max_depth=2, max_pages=300, enable_deep=False, enable_dark=False, tor_port=9050, **kwargs):
    """Compatibility wrapper that calls run_crawler with orchestrator args."""
    depth = max_depth if max_depth else 2
    return run_crawler(target, depth)
