#!/usr/bin/env python3
import sys
import json
import re
import time
import threading
import queue
import sqlite3
from pathlib import Path
from urllib.parse import urljoin, urlparse, unquote, urlunparse
from collections import defaultdict
from dataclasses import dataclass
from typing import Set, List, Dict, Optional, Tuple
import requests
from requests.exceptions import Timeout, RequestException
from html.parser import HTMLParser
import signal
import os

@dataclass
class Config:
    target: str = ""
    depth: int = 2
    timeout: int = 6
    follow_js: bool = True
    max_mutations: int = 12
    max_js_files: int = 25
    threads: int = 5

class LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.links = []
        self.base = base_url
    
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        href_keys = ['href', 'src', 'action']
        for key in href_keys:
            if key in attrs:
                full = urljoin(self.base, attrs[key])
                if urlparse(full).netloc == urlparse(self.base).netloc:
                    self.links.append(full)

def get_js_paths(content, base_url):
    paths = set()
    quote_pattern = r'["\'](/[a-zA-Z0-9_\/\.\-]{3,})["\']'
    for match in re.finditer(quote_pattern, content):
        path = match.group(1)
        if path.startswith('/'):
            paths.add(urljoin(base_url, path))
    
    import_pattern = r'(?:import|require)\(?\s*["\']([^"\']+\.js)["\']'
    for match in re.finditer(import_pattern, content):
        paths.add(urljoin(base_url, match.group(1)))
    
    fetch_pattern = r'fetch\(["\']([^"\']+)["\']\)'
    for match in re.finditer(fetch_pattern, content):
        path = match.group(1)
        if path.startswith('/'):
            paths.add(urljoin(base_url, path))
    
    return list(paths)

def normalize_url(url):
    parsed = urlparse(url)
    path = unquote(parsed.path).rstrip('/')
    if not path:
        path = '/'
    normalized = parsed._replace(path=path, query='', fragment='')
    return urlunparse(normalized)

def extract_base_path(url):
    parsed = urlparse(url)
    path = unquote(parsed.path).rstrip('/')
    if not path:
        path = '/'
    return path

def smart_mutations(base_path):
    mutations = []
    
    if base_path == '/':
        mutations.extend(['/api', '/admin', '/internal', '/v1', '/v2'])
        return mutations
    
    parts = base_path.split('/')
    if len(parts) <= 1:
        return mutations
    
    last_part = parts[-1]
    
    suffixes = ['_old', '_bak', '_dev', '_test', '_new', '2', '_v1', '_v2']
    for suf in suffixes:
        mutations.append('/'.join(parts[:-1] + [last_part + suf]))
    
    extensions = ['.json', '.php', '.html', '.xml', '.yaml', '.txt']
    for ext in extensions:
        mutations.append(base_path + ext)
    
    if 'api' in base_path.lower():
        for version in ['/v1', '/v2', '/v3', '/internal', '/private']:
            if version not in base_path:
                new_parts = parts.copy()
                for i in range(len(new_parts)):
                    if 'api' in new_parts[i].lower():
                        new_parts.insert(i + 1, version.lstrip('/'))
                        mutations.append('/'.join(new_parts))
                        break
    
    if len(last_part) > 2:
        mutations.append('/'.join(parts[:-1] + [last_part + 's']))
        if last_part.endswith('s'):
            mutations.append('/'.join(parts[:-1] + [last_part[:-1]]))
    
    truncated = '/'.join(parts[:-1] + [last_part[:len(last_part)//2]])
    if len(truncated.split('/')[-1]) >= 2:
        mutations.append(truncated)
    
    return mutations[:12]

class DBWriter(threading.Thread):
    def __init__(self, db_path):
        super().__init__(daemon=True)
        self.queue = queue.Queue()
        self.running = True
        self.db_path = db_path
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute('''
            CREATE TABLE IF NOT EXISTS responses (
                url TEXT PRIMARY KEY,
                path TEXT,
                status INTEGER,
                length INTEGER,
                headers TEXT,
                time REAL
            )
        ''')
    
    def run(self):
        while self.running:
            try:
                item = self.queue.get(timeout=1)
                if item is None:
                    break
                self.db.execute(
                    "INSERT OR REPLACE INTO responses VALUES (?, ?, ?, ?, ?, ?)",
                    item
                )
                self.db.commit()
            except queue.Empty:
                continue
    
    def stop(self):
        self.running = False
        self.queue.put(None)
        self.join()
        self.db.close()

class NearPath:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        
        self.visited_urls = set()
        self.visited_paths = {}
        self.priority_queue = queue.PriorityQueue()
        self.lock = threading.Lock()
        self.results = defaultdict(dict)
        self.js_files_fetched = 0
        self.fake_404 = None
        self.stop_event = threading.Event()
        
        self.base_dir = Path("nearpath_results")
        self.base_dir.mkdir(exist_ok=True)
        
        parsed_target = urlparse(self.config.target)
        domain = parsed_target.netloc
        self.domain_dir = self.base_dir / domain
        self.domain_dir.mkdir(exist_ok=True)
        
        self.db_path = self.domain_dir / 'responses.db'
        self.db_writer = DBWriter(str(self.db_path))
        self.db_writer.start()
    
    def save_results(self):
        discovered_path = self.domain_dir / 'discovered.txt'
        with open(discovered_path, 'w') as f:
            for path in self.results:
                for url, data in self.results[path].items():
                    f.write(f"{url} - {data['status']} - {data['length']}b\n")
        
        json_path = self.domain_dir / 'target.json'
        with open(json_path, 'w') as f:
            json.dump(dict(self.results), f, indent=2)
    
    def detect_fake_404(self):
        test_url = f"{self.config.target}/nearpath_fake_404_test_xyz123"
        try:
            resp = self.session.get(test_url, timeout=self.config.timeout, allow_redirects=False)
            self.fake_404 = {
                'status': resp.status_code,
                'length': len(resp.content),
                'headers': dict(resp.headers)
            }
        except:
            self.fake_404 = {'status': 404, 'length': 0, 'headers': {}}
    
    def is_real_response(self, response):
        if not self.fake_404:
            return True
        
        if response.status_code != self.fake_404['status']:
            return True
        
        if len(response.content) != self.fake_404['length']:
            return True
        
        for key in ['Content-Type', 'Server', 'X-Powered-By']:
            if response.headers.get(key) != self.fake_404['headers'].get(key):
                return True
        
        return False
    
    def fetch(self, url, method='GET'):
        if self.stop_event.is_set():
            return None
        
        try:
            if method == 'HEAD':
                resp = self.session.head(url, timeout=self.config.timeout, allow_redirects=True)
                return resp
            else:
                resp = self.session.get(url, timeout=self.config.timeout, allow_redirects=True)
                return resp
        except (Timeout, RequestException):
            return None
    
    def process_url(self, url, depth, priority=0):
        if depth > self.config.depth:
            return
        
        norm_url = normalize_url(url)
        base_path = extract_base_path(url)
        
        with self.lock:
            if norm_url in self.visited_urls:
                return
            
            best_priority = self.visited_paths.get(base_path, -1)
            if priority <= best_priority:
                return
            
            self.visited_urls.add(norm_url)
            self.visited_paths[base_path] = priority
        
        print(f"\033[36m[>]\033[0m {base_path}")
        
        head_resp = self.fetch(norm_url, 'HEAD')
        if not head_resp:
            return
        
        if head_resp.status_code in [200, 403, 401, 301, 302, 500]:
            get_resp = self.fetch(norm_url, 'GET')
            if get_resp and self.is_real_response(get_resp):
                with self.lock:
                    self.results[base_path][norm_url] = {
                        'status': get_resp.status_code,
                        'length': len(get_resp.content),
                        'type': get_resp.headers.get('Content-Type', ''),
                        'priority': priority
                    }
                
                self.db_writer.queue.put((
                    norm_url,
                    base_path,
                    get_resp.status_code,
                    len(get_resp.content),
                    json.dumps(dict(get_resp.headers)),
                    time.time()
                ))
                
                if get_resp.status_code == 200:
                    color = "\033[32m"
                elif get_resp.status_code in [403, 401]:
                    color = "\033[33m"
                elif get_resp.status_code >= 500:
                    color = "\033[31m"
                else:
                    color = "\033[35m"
                
                print(f"{color}[+] {base_path} ({get_resp.status_code}, {len(get_resp.content)} bytes)\033[0m")
                
                if get_resp.status_code == 200:
                    if get_resp.headers.get('Content-Type', '').startswith('text/html'):
                        self.extract_links(get_resp.text, norm_url, priority + 1)
                    
                    if self.config.follow_js:
                        content_type = get_resp.headers.get('Content-Type', '')
                        if 'javascript' in content_type or url.endswith('.js'):
                            self.process_js(get_resp.text, norm_url, priority + 2)
                
                if depth < self.config.depth:
                    self.queue_mutations(base_path, norm_url, depth + 1, priority - 1)
    
    def extract_links(self, html, base_url, priority):
        parser = LinkExtractor(base_url)
        parser.feed(html)
        for link in parser.links:
            self.priority_queue.put((-priority, link, 1))
    
    def process_js(self, content, base_url, priority):
        with self.lock:
            if self.js_files_fetched >= self.config.max_js_files:
                return
            self.js_files_fetched += 1
        
        paths = get_js_paths(content, base_url)
        for path in paths:
            if path.endswith('.js'):
                self.priority_queue.put((-(priority + 1), path, 0))
        
        js_sources_path = self.domain_dir / 'js_sources.txt'
        with open(js_sources_path, 'a') as f:
            f.write(f"// From {base_url}\n")
            f.write(content[:500] + "\n\n")
    
    def queue_mutations(self, base_path, base_url, depth, priority):
        mutations = smart_mutations(base_path)
        for mut in mutations:
            full_url = urljoin(base_url, mut)
            self.priority_queue.put((-priority, full_url, depth))
    
    def worker(self):
        while not self.stop_event.is_set():
            try:
                neg_priority, url, depth = self.priority_queue.get(timeout=1)
                priority = -neg_priority
                self.process_url(url, depth, priority)
                self.priority_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                if not self.stop_event.is_set():
                    pass
    
    def run(self):
        print(f"\n[ NearPath — Scanning {urlparse(self.config.target).netloc} ]\n")
        
        self.detect_fake_404()
        self.priority_queue.put((-10, self.config.target, 0))
        
        threads = []
        for _ in range(min(self.config.threads, 10)):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        try:
            last_active = time.time()
            while not self.stop_event.is_set():
                time.sleep(0.5)
                
                if self.priority_queue.empty():
                    alive = sum(1 for t in threads if t.is_alive())
                    if alive == 0:
                        break
                    if time.time() - last_active > 5:
                        break
                else:
                    last_active = time.time()
                    
        except KeyboardInterrupt:
            pass
        
        self.stop_event.set()
        
        for t in threads:
            t.join(timeout=2)
        
        self.db_writer.stop()
        self.save_results()
        
        valid = 0
        for path in self.results:
            for url_data in self.results[path].values():
                if url_data['status'] in [200, 403, 401, 500]:
                    valid += 1
        
        print(f"\n\033[32m[+] Found {valid} interesting endpoints across {len(self.results)} unique paths\033[0m")
        print(f"\033[32m[+] Results saved to {self.domain_dir}/\033[0m")

def main():
    config = Config()
    
    print("\n[ NearPath — Guided Surface Fuzzer ]\n")
    
    try:
        config.target = input("Target URL: ").strip()
        if not config.target.startswith(('http://', 'https://')):
            config.target = 'http://' + config.target
        
        depth_str = input("Max depth (default 2): ").strip()
        config.depth = int(depth_str) if depth_str else 2
        
        timeout_str = input("Timeout per request (seconds, default 6): ").strip()
        config.timeout = int(timeout_str) if timeout_str else 6
        
        js_str = input("Follow JS imports? (Y/n): ").strip().lower()
        config.follow_js = js_str != 'n'
        
        mut_str = input("Max mutations per path (default 12): ").strip()
        config.max_mutations = int(mut_str) if mut_str else 12
    except (ValueError, KeyboardInterrupt):
        print("\nInvalid input")
        sys.exit(1)
    
    np = NearPath(config)
    
    def signal_handler(sig, frame):
        print("\n\033[33m[!] Shutting down...\033[0m")
        np.stop_event.set()
    
    signal.signal(signal.SIGINT, signal_handler)
    
    np.run()

if __name__ == "__main__":
    main()
