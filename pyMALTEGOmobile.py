#!/usr/bin/env python3
import json
import requests
import socket
import dns.resolver
import whois
import ipaddress
import re
import hashlib
import base64
import os
import sys
import time
import threading
import queue
from datetime import datetime
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import ssl
import csv
import sqlite3
from collections import defaultdict


class Colors:
    ORANGE = '\033[38;5;208m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


BANNER = f"""
{Colors.ORANGE}
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-:...MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=::.......MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM*:...*--=M====MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-...*-M--:.........*-MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=...:M=*...:::*--*:::...:=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM...-MMM-.:MM-:.....-MM:...:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM:..=MMMMMM-:..........:*M*..:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM:..-MMMMMM:..:-=MMMMM-:..:=-...MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM...MMMMMM:..*MMMM==MMMM-...M*..*MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=..:MMMMM=..:MMM-....-MMM*..*M...MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-..*MMMMM*..-MMM......MMMM===M...MM===MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=..:MMMMM-..:MMM-....=MMMMMMMM...M-..*MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM...MMMMMM...*MMMM==MMMMMMMMM*..*M:..=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM:..*MMMMMM:..:-MMMMMMMMMMMM-...M=..:MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM...=MMMMM=*:.....MMMMMMMM*..:==...=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM...-MMM:.*MM*...MMMMMM*....MM...=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=...:M=:...:::*---*::...:=M:...=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM-...*==-*..........*-==*...*MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM*....--=M==--==M=--....*=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=::..............::-MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM*:.......*=MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
{Colors.RESET}
"""


class EntityType(Enum):
    DOMAIN = "maltego.Domain"
    IP_ADDRESS = "maltego.IPv4Address"
    IPV6_ADDRESS = "maltego.IPv6Address"
    URL = "maltego.URL"
    EMAIL = "maltego.EmailAddress"
    PERSON = "maltego.Person"
    ORGANIZATION = "maltego.Organization"
    LOCATION = "maltego.Location"
    PHONE = "maltego.PhoneNumber"
    FILE = "maltego.File"
    HASH = "maltego.Hash"
    NETBLOCK = "maltego.Netblock"
    AS = "maltego.AS"
    DNS_NAME = "maltego.DNSName"
    USERNAME = "maltego.Username"
    SOCIAL_MEDIA = "maltego.SocialMedia"
    COMPANY = "maltego.Company"


@dataclass
class Entity:
    type: str
    value: str
    weight: int = 100
    properties: Dict[str, Any] = None
    timestamp: str = None
    source: str = None
    
    def __post_init__(self):
        if self.properties is None:
            self.properties = {}
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class Link:
    source: Entity
    target: Entity
    label: str = ""
    weight: int = 100
    directed: bool = True
    properties: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.properties is None:
            self.properties = {}
    
    def to_dict(self) -> Dict:
        return {
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "label": self.label,
            "weight": self.weight,
            "directed": self.directed,
            "properties": self.properties
        }


class MaltegoDatabase:
    def __init__(self, db_path="maltego.db"):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT,
                value TEXT,
                weight INTEGER,
                properties TEXT,
                timestamp TEXT,
                source TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER,
                target_id INTEGER,
                label TEXT,
                weight INTEGER,
                directed INTEGER,
                properties TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                type TEXT,
                timestamp TEXT,
                results TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_entity(self, entity: Entity) -> int:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO entities (type, value, weight, properties, timestamp, source) VALUES (?, ?, ?, ?, ?, ?)",
            (entity.type, entity.value, entity.weight, json.dumps(entity.properties), entity.timestamp, entity.source)
        )
        entity_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return entity_id
    
    def get_entities(self, type_filter: str = None) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        if type_filter:
            cursor.execute("SELECT * FROM entities WHERE type = ?", (type_filter,))
        else:
            cursor.execute("SELECT * FROM entities")
        results = cursor.fetchall()
        conn.close()
        return results
    
    def search_entities(self, query: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM entities WHERE value LIKE ?", (f"%{query}%",))
        results = cursor.fetchall()
        conn.close()
        return results


class AdvancedScanner:
    def __init__(self):
        self.results = {}
        self.max_threads = 10
    
    def port_scan_advanced(self, target: str, ports: List[int] = None, timeout: float = 1.0) -> Dict:
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        
        results = {"open": [], "closed": [], "filtered": [], "services": {}}
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    results["open"].append(port)
                    try:
                        service = socket.getservbyport(port)
                        results["services"][port] = service
                    except:
                        results["services"][port] = "unknown"
                elif result == 111:
                    results["filtered"].append(port)
                else:
                    results["closed"].append(port)
            except:
                results["filtered"].append(port)
        
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            thread.start()
            threads.append(thread)
            if len(threads) >= self.max_threads:
                for t in threads:
                    t.join()
                threads = []
        
        for thread in threads:
            thread.join()
        
        return results
    
    def dns_enum_advanced(self, domain: str) -> Dict:
        results = {
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "ns_records": [],
            "txt_records": [],
            "cname_records": [],
            "ptr_records": [],
            "soa_records": [],
            "srv_records": [],
            "subdomains": []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    if record_type == 'MX':
                        results[f"{record_type.lower()}_records"].append(str(rdata.exchange))
                    else:
                        results[f"{record_type.lower()}_records"].append(str(rdata))
            except:
                pass
        
        try:
            ip = socket.gethostbyname(domain)
            answers = dns.resolver.resolve(ip, 'PTR')
            for rdata in answers:
                results["ptr_records"].append(str(rdata))
        except:
            pass
        
        subdomains = self.enumerate_subdomains(domain)
        results["subdomains"] = subdomains
        
        return results
    
    def enumerate_subdomains(self, domain: str, wordlist: List[str] = None) -> List[str]:
        if wordlist is None:
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test', 'ns',
                'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3', 'mail2',
                'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx', 'static', 'docs',
                'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar', 'wiki', 'web',
                'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal', 'video',
                'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns', 'sf',
                'apps', 'backup', 'cloud', 'download', 'exchange', 'git', 'help',
                'host', 'info', 'internal', 'ipv6', 'jobs', 'log', 'monitor', 'music',
                'office', 'online', 'panel', 'partner', 'pay', 'payment', 'server',
                'service', 'shop', 'site', 'stage', 'storage', 'store', 'test',
                'tools', 'upload', 'user', 'webapp', 'wiki', 'wp', 'cdn', 'api',
                'grafana', 'kibana', 'elasticsearch', 'jenkins', 'gitlab', 'confluence',
                'jira', 'nexus', 'artifactory', 'docker', 'kubernetes', 'k8s',
                'prometheus', 'alertmanager', 'zabbix', 'nagios', 'icinga'
            ]
        
        found = []
        for sub in wordlist:
            try:
                full_domain = f"{sub}.{domain}"
                dns.resolver.resolve(full_domain, 'A')
                found.append(full_domain)
            except:
                pass
        
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                if cert and 'subjectAltName' in cert:
                    for san in cert['subjectAltName']:
                        if san[0] == 'DNS' and san[1].endswith(domain) and san[1] != domain:
                            found.append(san[1])
        except:
            pass
        
        return sorted(set(found))
    
    def whois_advanced(self, target: str) -> Dict:
        results = {}
        try:
            w = whois.whois(target)
            results = {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "whois_server": w.whois_server,
                "referral_url": w.referral_url,
                "updated_date": str(w.updated_date),
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "dnssec": w.dnssec,
                "name": w.name,
                "org": w.org,
                "address": w.address,
                "city": w.city,
                "state": w.state,
                "zipcode": w.zipcode,
                "country": w.country
            }
        except Exception as e:
            results = {"error": str(e)}
        return results
    
    def ssl_certificate_info(self, domain: str, port: int = 443) -> Dict:
        results = {}
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, port))
                cert = s.getpeercert()
                
                results = {
                    "subject": str(cert.get('subject', [])),
                    "issuer": str(cert.get('issuer', [])),
                    "version": cert.get('version', 0),
                    "serial_number": cert.get('serialNumber', ''),
                    "not_before": cert.get('notBefore', ''),
                    "not_after": cert.get('notAfter', ''),
                    "subject_alt_name": cert.get('subjectAltName', [])
                }
        except Exception as e:
            results = {"error": str(e)}
        return results
    
    def http_headers_analyze(self, url: str) -> Dict:
        results = {}
        try:
            response = requests.get(url, timeout=10, verify=False)
            results = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "server": response.headers.get('Server', ''),
                "cookies": response.cookies.get_dict(),
                "content_type": response.headers.get('Content-Type', ''),
                "content_length": response.headers.get('Content-Length', ''),
                "security_headers": {
                    "strict_transport_security": response.headers.get('Strict-Transport-Security', ''),
                    "content_security_policy": response.headers.get('Content-Security-Policy', ''),
                    "x_frame_options": response.headers.get('X-Frame-Options', ''),
                    "x_content_type_options": response.headers.get('X-Content-Type-Options', ''),
                    "referrer_policy": response.headers.get('Referrer-Policy', ''),
                    "permissions_policy": response.headers.get('Permissions-Policy', '')
                }
            }
        except Exception as e:
            results = {"error": str(e)}
        return results
    
    def email_analyze(self, email: str) -> Dict:
        results = {
            "email": email,
            "local_part": email.split('@')[0] if '@' in email else '',
            "domain": email.split('@')[1] if '@' in email else '',
            "valid_format": bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)),
            "domain_info": {},
            "spf": None,
            "dmarc": None
        }
        
        if results['domain']:
            try:
                answers = dns.resolver.resolve(results['domain'], 'MX')
                results['domain_info']['mx_records'] = [str(r.exchange) for r in answers]
            except:
                pass
            
            try:
                answers = dns.resolver.resolve(results['domain'], 'TXT')
                for r in answers:
                    if 'v=spf1' in str(r):
                        results['spf'] = str(r)
                        break
            except:
                pass
            
            try:
                dmarc_domain = f"_dmarc.{results['domain']}"
                answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                for r in answers:
                    if 'v=DMARC1' in str(r):
                        results['dmarc'] = str(r)
                        break
            except:
                pass
        
        return results
    
    def network_geo_lookup(self, ip: str) -> Dict:
        results = {}
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            results = {
                "status": data.get('status', ''),
                "country": data.get('country', ''),
                "country_code": data.get('countryCode', ''),
                "region": data.get('region', ''),
                "region_name": data.get('regionName', ''),
                "city": data.get('city', ''),
                "zip": data.get('zip', ''),
                "lat": data.get('lat', 0),
                "lon": data.get('lon', 0),
                "timezone": data.get('timezone', ''),
                "isp": data.get('isp', ''),
                "org": data.get('org', ''),
                "as": data.get('as', '')
            }
        except Exception as e:
            results = {"error": str(e)}
        return results
    
    def social_media_discover(self, username: str) -> Dict:
        platforms = {
            'twitter': f"https://twitter.com/{username}",
            'instagram': f"https://instagram.com/{username}",
            'facebook': f"https://facebook.com/{username}",
            'linkedin': f"https://linkedin.com/in/{username}",
            'github': f"https://github.com/{username}",
            'gitlab': f"https://gitlab.com/{username}",
            'reddit': f"https://reddit.com/user/{username}",
            'youtube': f"https://youtube.com/@{username}",
            'vimeo': f"https://vimeo.com/{username}",
            'flickr': f"https://flickr.com/people/{username}",
            'soundcloud': f"https://soundcloud.com/{username}",
            'spotify': f"https://open.spotify.com/user/{username}",
            'twitch': f"https://twitch.tv/{username}",
            'telegram': f"https://t.me/{username}",
            'tiktok': f"https://tiktok.com/@{username}",
            'pinterest': f"https://pinterest.com/{username}",
            'tumblr': f"https://{username}.tumblr.com",
            'medium': f"https://medium.com/@{username}",
            'devto': f"https://dev.to/{username}",
            'hashnode': f"https://hashnode.com/@{username}"
        }
        
        results = {}
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    results[platform] = {"exists": True, "url": url}
                elif response.status_code == 404:
                    results[platform] = {"exists": False, "url": url}
                else:
                    results[platform] = {"exists": None, "url": url}
            except:
                results[platform] = {"exists": None, "url": url}
        
        return results
    
    def file_analyze(self, file_path: str) -> Dict:
        results = {
            "path": file_path,
            "exists": os.path.exists(file_path),
            "size": None,
            "hash": {},
            "type": None,
            "entropy": None
        }
        
        if results["exists"]:
            stat = os.stat(file_path)
            results["size"] = stat.st_size
            results["created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
            results["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            
            with open(file_path, 'rb') as f:
                data = f.read()
                results["hash"]["md5"] = hashlib.md5(data).hexdigest()
                results["hash"]["sha1"] = hashlib.sha1(data).hexdigest()
                results["hash"]["sha256"] = hashlib.sha256(data).hexdigest()
                results["hash"]["sha512"] = hashlib.sha512(data).hexdigest()
                
                if len(data) > 0:
                    entropy = 0
                    for i in range(256):
                        p = data.count(i) / len(data)
                        if p > 0:
                            entropy -= p * (p.bit_length() - 1)
                    results["entropy"] = entropy
        
        return results
    
    def hash_lookup(self, hash_value: str) -> Dict:
        results = {
            "hash": hash_value,
            "type": None,
            "sources": {}
        }
        
        if len(hash_value) == 32:
            results["type"] = "MD5"
        elif len(hash_value) == 40:
            results["type"] = "SHA1"
        elif len(hash_value) == 64:
            results["type"] = "SHA256"
        elif len(hash_value) == 128:
            results["type"] = "SHA512"
        
        try:
            response = requests.get(f"https://www.google.com/search?q={hash_value}", timeout=5)
            results["sources"]["google"] = "found" if hash_value in response.text else "not_found"
        except:
            pass
        
        return results


class ReportGenerator:
    def __init__(self, graph):
        self.graph = graph
    
    def generate_html_report(self, filename: str):
        html = f'''<!DOCTYPE html>
<html>
<head>
    <title>Maltego Intelligence Report</title>
    <style>
        body {{ font-family: Arial; margin: 20px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: #16213e; padding: 20px; border-radius: 10px; }}
        h1 {{ color: #ff6b35; border-bottom: 2px solid #ff6b35; padding-bottom: 10px; }}
        .stats {{ display: flex; gap: 20px; flex-wrap: wrap; }}
        .stat-box {{ background: #ff6b35; color: white; padding: 15px; border-radius: 5px; flex: 1; min-width: 150px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #ff6b35; color: white; }}
        .timestamp {{ color: #888; font-size: 0.9em; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Maltego Intelligence Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="stats">
            <div class="stat-box">Entities: {len(self.graph.entities)}</div>
            <div class="stat-box">Links: {len(self.graph.links)}</div>
        </div>
        
        <h2>Entities</h2>
        <table>
            <tr><th>Type</th><th>Value</th><th>Weight</th><th>Source</th></tr>
'''
        for entity in list(self.graph.entities.values())[:100]:
            html += f'''
            <tr>
                <td>{entity.type}</td>
                <td>{entity.value}</td>
                <td>{entity.weight}</td>
                <td>{entity.source or 'N/A'}</td>
            </tr>
'''
        html += '''
        </table>
        
        <h2>Links</h2>
        <table>
            <tr><th>Source</th><th>Target</th><th>Label</th><th>Weight</th></tr>
'''
        for link in self.graph.links[:100]:
            html += f'''
            <tr>
                <td>{link.source.value}</td>
                <td>{link.target.value}</td>
                <td>{link.label or 'N/A'}</td>
                <td>{link.weight}</td>
            </tr>
'''
        html += '''
        </table>
    </div>
</body>
</html>
'''
        with open(filename, 'w') as f:
            f.write(html)
    
    def generate_csv_report(self, filename: str):
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Entity Type', 'Entity Value', 'Weight', 'Properties'])
            for entity in self.graph.entities.values():
                writer.writerow([entity.type, entity.value, entity.weight, json.dumps(entity.properties)])
    
    def generate_mtz_report(self, filename: str):
        data = {
            "entities": [e.to_dict() for e in self.graph.entities.values()],
            "links": [l.to_dict() for l in self.graph.links],
            "metadata": {
                "generated": datetime.now().isoformat(),
                "version": "2.0"
            }
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)


class MaltegoGraph:
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.links: List[Link] = []
        self.metadata: Dict[str, Any] = {}
    
    def add_entity(self, entity: Entity):
        key = f"{entity.type}:{entity.value}"
        if key not in self.entities:
            self.entities[key] = entity
        return key
    
    def add_link(self, link: Link):
        self.links.append(link)
        self.add_entity(link.source)
        self.add_entity(link.target)
    
    def get_entity(self, value: str) -> Optional[Entity]:
        for entity in self.entities.values():
            if entity.value == value:
                return entity
        return None
    
    def find_connections(self, entity_value: str) -> List[Dict]:
        connections = []
        for link in self.links:
            if link.source.value == entity_value:
                connections.append({
                    "entity": link.target,
                    "direction": "outgoing",
                    "label": link.label,
                    "weight": link.weight
                })
            elif link.target.value == entity_value:
                connections.append({
                    "entity": link.source,
                    "direction": "incoming",
                    "label": link.label,
                    "weight": link.weight
                })
        return connections
    
    def get_statistics(self) -> Dict:
        stats = {
            "total_entities": len(self.entities),
            "total_links": len(self.links),
            "entity_types": defaultdict(int),
            "link_labels": defaultdict(int),
            "avg_connections": 0
        }
        
        for entity in self.entities.values():
            stats["entity_types"][entity.type] += 1
        
        for link in self.links:
            stats["link_labels"][link.label] += 1
        
        if len(self.entities) > 0:
            total_connections = sum(len(self.find_connections(e.value)) for e in self.entities.values())
            stats["avg_connections"] = total_connections / len(self.entities)
        
        return dict(stats)
    
    def export_json(self, filename: str):
        data = {
            "entities": [e.to_dict() for e in self.entities.values()],
            "links": [l.to_dict() for l in self.links],
            "metadata": self.metadata
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)


class MaltezoTransform:
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.graph = MaltegoGraph()
        self.scanner = AdvancedScanner()
        self.db = MaltegoDatabase()
        self.report = ReportGenerator(self.graph)
    
    def run_domain_intelligence(self, domain: str) -> Dict:
        print(f"{Colors.CYAN}[+] Running domain intelligence for: {Colors.YELLOW}{domain}{Colors.RESET}")
        
        dns_results = self.scanner.dns_enum_advanced(domain)
        whois_results = self.scanner.whois_advanced(domain)
        ssl_results = self.scanner.ssl_certificate_info(domain)
        http_results = self.scanner.http_headers_analyze(f"https://{domain}")
        
        domain_entity = Entity(EntityType.DOMAIN.value, domain, properties={"source": "domain_intelligence"})
        self.graph.add_entity(domain_entity)
        
        for ip in dns_results.get('a_records', [])[:10]:
            ip_entity = Entity(EntityType.IP_ADDRESS.value, ip, properties={"source": "dns_lookup"})
            self.graph.add_entity(ip_entity)
            self.graph.add_link(Link(domain_entity, ip_entity, "resolves_to"))
            
            geo = self.scanner.network_geo_lookup(ip)
            if geo and 'country' in geo:
                location_entity = Entity(EntityType.LOCATION.value, f"{geo.get('city', '')}, {geo.get('country', '')}")
                self.graph.add_entity(location_entity)
                self.graph.add_link(Link(ip_entity, location_entity, "located_in"))
        
        for sub in dns_results.get('subdomains', [])[:20]:
            sub_entity = Entity(EntityType.DOMAIN.value, sub, properties={"source": "subdomain_enum"})
            self.graph.add_entity(sub_entity)
            self.graph.add_link(Link(domain_entity, sub_entity, "has_subdomain"))
        
        return {
            "domain": domain,
            "dns": dns_results,
            "whois": whois_results,
            "ssl": ssl_results,
            "http": http_results
        }
    
    def run_ip_intelligence(self, ip: str) -> Dict:
        print(f"{Colors.CYAN}[+] Running IP intelligence for: {Colors.YELLOW}{ip}{Colors.RESET}")
        
        ports = self.scanner.port_scan_advanced(ip)
        geo = self.scanner.network_geo_lookup(ip)
        
        reverse_dns = []
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            reverse_dns = [hostname]
        except:
            pass
        
        ip_entity = Entity(EntityType.IP_ADDRESS.value, ip, properties={"source": "ip_intelligence"})
        self.graph.add_entity(ip_entity)
        
        if reverse_dns:
            dns_entity = Entity(EntityType.DNS_NAME.value, reverse_dns[0], properties={"source": "reverse_dns"})
            self.graph.add_entity(dns_entity)
            self.graph.add_link(Link(ip_entity, dns_entity, "reverse_dns"))
        
        if geo and 'country' in geo:
            location = f"{geo.get('city', '')}, {geo.get('country', '')}"
            loc_entity = Entity(EntityType.LOCATION.value, location, properties={"source": "geo_ip"})
            self.graph.add_entity(loc_entity)
            self.graph.add_link(Link(ip_entity, loc_entity, "located_in"))
        
        for port in ports.get('open', [])[:10]:
            service = ports.get('services', {}).get(port, 'unknown')
            port_entity = Entity(f"Port_{port}", f"{port}/{service}", properties={"port": port, "service": service})
            self.graph.add_entity(port_entity)
            self.graph.add_link(Link(ip_entity, port_entity, f"open_port_{port}"))
        
        return {
            "ip": ip,
            "ports": ports,
            "geo": geo,
            "reverse_dns": reverse_dns
        }
    
    def run_email_intelligence(self, email: str) -> Dict:
        print(f"{Colors.CYAN}[+] Running email intelligence for: {Colors.YELLOW}{email}{Colors.RESET}")
        
        analysis = self.scanner.email_analyze(email)
        
        if analysis['domain']:
            self.run_domain_intelligence(analysis['domain'])
        
        email_entity = Entity(EntityType.EMAIL.value, email, properties={"source": "email_intelligence"})
        self.graph.add_entity(email_entity)
        
        username = analysis['local_part']
        social = self.scanner.social_media_discover(username)
        
        for platform, info in social.items():
            if info.get('exists'):
                sm_entity = Entity(EntityType.SOCIAL_MEDIA.value, f"{platform}:{username}", 
                                 properties={"platform": platform, "url": info.get('url')})
                self.graph.add_entity(sm_entity)
                self.graph.add_link(Link(email_entity, sm_entity, f"has_{platform}"))
        
        return {
            "email": email,
            "analysis": analysis,
            "social": social
        }
    
    def run_url_intelligence(self, url: str) -> Dict:
        print(f"{Colors.CYAN}[+] Running URL intelligence for: {Colors.YELLOW}{url}{Colors.RESET}")
        
        parsed = urlparse(url)
        domain = parsed.hostname
        
        http = self.scanner.http_headers_analyze(url)
        
        if domain:
            self.run_domain_intelligence(domain)
        
        url_entity = Entity(EntityType.URL.value, url, properties={"source": "url_intelligence"})
        self.graph.add_entity(url_entity)
        
        if domain:
            domain_entity = self.graph.get_entity(domain)
            if domain_entity:
                self.graph.add_link(Link(url_entity, domain_entity, "hosted_on"))
        
        return {
            "url": url,
            "http": http,
            "parsed": {
                "scheme": parsed.scheme,
                "hostname": parsed.hostname,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment
            }
        }
    
    def run_file_intelligence(self, file_path: str) -> Dict:
        print(f"{Colors.CYAN}[+] Running file intelligence for: {Colors.YELLOW}{file_path}{Colors.RESET}")
        
        analysis = self.scanner.file_analyze(file_path)
        
        file_entity = Entity(EntityType.FILE.value, file_path, properties=analysis)
        self.graph.add_entity(file_entity)
        
        if analysis.get('hash'):
            for hash_type, hash_value in analysis['hash'].items():
                hash_entity = Entity(EntityType.HASH.value, f"{hash_type}:{hash_value}", 
                                   properties={"hash_type": hash_type, "hash_value": hash_value})
                self.graph.add_entity(hash_entity)
                self.graph.add_link(Link(file_entity, hash_entity, f"{hash_type}_hash"))
        
        return analysis


class MaltegoMenu:
    def __init__(self):
        self.transform = MaltezoTransform("Advanced Maltego", "Full-featured OSINT tool")
        self.running = True
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_header(self):
        print(BANNER)
        print(f"{Colors.ORANGE}{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.ORANGE}{Colors.BOLD}      MALTEGO ADVANCED OSINT INSTRUMENT v3.0{Colors.RESET}")
        print(f"{Colors.ORANGE}{'='*60}{Colors.RESET}")
        print(f"{Colors.GREEN}      Entities: {len(self.transform.graph.entities)}{Colors.RESET}")
        print(f"{Colors.GREEN}      Links: {len(self.transform.graph.links)}{Colors.RESET}")
        print(f"{Colors.GREEN}      Database: {self.transform.db.db_path}{Colors.RESET}")
        print(f"{Colors.ORANGE}{'='*60}{Colors.RESET}")
    
    def main_menu(self):
        while self.running:
            self.clear_screen()
            self.print_header()
            print(f"\n{Colors.YELLOW}[1]{Colors.RESET} Domain Intelligence")
            print(f"{Colors.YELLOW}[2]{Colors.RESET} IP Intelligence")
            print(f"{Colors.YELLOW}[3]{Colors.RESET} Email Intelligence")
            print(f"{Colors.YELLOW}[4]{Colors.RESET} URL Intelligence")
            print(f"{Colors.YELLOW}[5]{Colors.RESET} File Intelligence")
            print(f"{Colors.YELLOW}[6]{Colors.RESET} WHOIS Lookup")
            print(f"{Colors.YELLOW}[7]{Colors.RESET} DNS Enumeration")
            print(f"{Colors.YELLOW}[8]{Colors.RESET} Port Scanner")
            print(f"{Colors.YELLOW}[9]{Colors.RESET} Subdomain Scanner")
            print(f"{Colors.YELLOW}[10]{Colors.RESET} SSL Certificate Analysis")
            print(f"{Colors.YELLOW}[11]{Colors.RESET} Social Media Discovery")
            print(f"{Colors.YELLOW}[12]{Colors.RESET} Hash Lookup")
            print(f"{Colors.YELLOW}[13]{Colors.RESET} Network Geo Location")
            print(f"{Colors.YELLOW}[14]{Colors.RESET} HTTP Headers Analysis")
            print(f"{Colors.YELLOW}[15]{Colors.RESET} Export Results")
            print(f"{Colors.YELLOW}[16]{Colors.RESET} Generate Report")
            print(f"{Colors.YELLOW}[17]{Colors.RESET} View Graph")
            print(f"{Colors.YELLOW}[18]{Colors.RESET} Graph Statistics")
            print(f"{Colors.YELLOW}[19]{Colors.RESET} Search Entities")
            print(f"{Colors.YELLOW}[20]{Colors.RESET} Clear Data")
            print(f"{Colors.YELLOW}[21]{Colors.RESET} Database Management")
            print(f"{Colors.YELLOW}[22]{Colors.RESET} Batch Scan")
            print(f"{Colors.RED}[0]{Colors.RESET} Exit")
            print(f"{Colors.ORANGE}{'='*60}{Colors.RESET}")
            
            choice = input(f"{Colors.GREEN}Select option (0-22): {Colors.RESET}")
            self.handle_choice(choice)
    
    def handle_choice(self, choice: str):
        if choice == "1":
            domain = input(f"{Colors.CYAN}Enter domain: {Colors.RESET}")
            results = self.transform.run_domain_intelligence(domain)
            print(f"\n{Colors.GREEN}[+] Domain intelligence completed{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Found {len(results['dns'].get('a_records', []))} A records{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Found {len(results['dns'].get('subdomains', []))} subdomains{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "2":
            ip = input(f"{Colors.CYAN}Enter IP address: {Colors.RESET}")
            results = self.transform.run_ip_intelligence(ip)
            print(f"\n{Colors.GREEN}[+] IP intelligence completed{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Found {len(results['ports'].get('open', []))} open ports{Colors.RESET}")
            if results.get('geo'):
                print(f"{Colors.GREEN}[+] Location: {results['geo'].get('city', '')}, {results['geo'].get('country', '')}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "3":
            email = input(f"{Colors.CYAN}Enter email: {Colors.RESET}")
            results = self.transform.run_email_intelligence(email)
            print(f"\n{Colors.GREEN}[+] Email intelligence completed{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Domain: {results['analysis'].get('domain', '')}{Colors.RESET}")
            if results.get('social'):
                found = sum(1 for v in results['social'].values() if v.get('exists'))
                print(f"{Colors.GREEN}[+] Found {found} social media profiles{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "4":
            url = input(f"{Colors.CYAN}Enter URL: {Colors.RESET}")
            results = self.transform.run_url_intelligence(url)
            print(f"\n{Colors.GREEN}[+] URL intelligence completed{Colors.RESET}")
            print(f"{Colors.GREEN}[+] Status code: {results['http'].get('status_code', 'N/A')}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "5":
            file_path = input(f"{Colors.CYAN}Enter file path: {Colors.RESET}")
            results = self.transform.run_file_intelligence(file_path)
            print(f"\n{Colors.GREEN}[+] File analysis completed{Colors.RESET}")
            if results.get('exists'):
                print(f"{Colors.GREEN}[+] Size: {results.get('size', 0)} bytes{Colors.RESET}")
                print(f"{Colors.GREEN}[+] MD5: {results.get('hash', {}).get('md5', 'N/A')}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "6":
            target = input(f"{Colors.CYAN}Enter domain or IP: {Colors.RESET}")
            results = self.transform.scanner.whois_advanced(target)
            print(f"\n{Colors.GREEN}[+] WHOIS Results:{Colors.RESET}")
            for key, value in results.items():
                if value:
                    print(f"{Colors.YELLOW}  {key}: {Colors.WHITE}{value}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "7":
            domain = input(f"{Colors.CYAN}Enter domain: {Colors.RESET}")
            results = self.transform.scanner.dns_enum_advanced(domain)
            print(f"\n{Colors.GREEN}[+] DNS Records:{Colors.RESET}")
            for record_type, records in results.items():
                if records:
                    print(f"{Colors.YELLOW}  {record_type}: {Colors.WHITE}{', '.join(str(r) for r in records[:5])}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "8":
            target = input(f"{Colors.CYAN}Enter IP address: {Colors.RESET}")
            port_range = input(f"{Colors.CYAN}Enter ports (comma separated, or press Enter for default): {Colors.RESET}")
            if port_range:
                ports = [int(p.strip()) for p in port_range.split(',')]
            else:
                ports = None
            results = self.transform.scanner.port_scan_advanced(target, ports)
            print(f"\n{Colors.GREEN}[+] Port Scan Results:{Colors.RESET}")
            print(f"{Colors.GREEN}  Open ports: {Colors.WHITE}{', '.join(str(p) for p in results['open'])}{Colors.RESET}")
            print(f"{Colors.GREEN}  Filtered: {Colors.WHITE}{len(results['filtered'])}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "9":
            domain = input(f"{Colors.CYAN}Enter domain: {Colors.RESET}")
            subdomains = self.transform.scanner.enumerate_subdomains(domain)
            print(f"\n{Colors.GREEN}[+] Found {len(subdomains)} subdomains:{Colors.RESET}")
            for sub in subdomains[:20]:
                print(f"{Colors.YELLOW}  -> {Colors.WHITE}{sub}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "10":
            domain = input(f"{Colors.CYAN}Enter domain: {Colors.RESET}")
            results = self.transform.scanner.ssl_certificate_info(domain)
            print(f"\n{Colors.GREEN}[+] SSL Certificate:{Colors.RESET}")
            if results:
                print(f"{Colors.YELLOW}  Subject: {Colors.WHITE}{results.get('subject', '')}{Colors.RESET}")
                print(f"{Colors.YELLOW}  Issuer: {Colors.WHITE}{results.get('issuer', '')}{Colors.RESET}")
                print(f"{Colors.YELLOW}  Valid until: {Colors.WHITE}{results.get('not_after', '')}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "11":
            username = input(f"{Colors.CYAN}Enter username: {Colors.RESET}")
            results = self.transform.scanner.social_media_discover(username)
            print(f"\n{Colors.GREEN}[+] Social Media Discovery:{Colors.RESET}")
            found = 0
            for platform, info in results.items():
                if info.get('exists'):
                    print(f"{Colors.GREEN}  [FOUND] {Colors.YELLOW}{platform}: {Colors.WHITE}{info.get('url')}{Colors.RESET}")
                    found += 1
            print(f"\n{Colors.GREEN}  Total found: {Colors.WHITE}{found}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "12":
            hash_value = input(f"{Colors.CYAN}Enter hash: {Colors.RESET}")
            results = self.transform.scanner.hash_lookup(hash_value)
            print(f"\n{Colors.GREEN}[+] Hash Analysis:{Colors.RESET}")
            print(f"{Colors.YELLOW}  Type: {Colors.WHITE}{results.get('type', 'Unknown')}{Colors.RESET}")
            print(f"{Colors.YELLOW}  Sources: {Colors.WHITE}{', '.join(results.get('sources', {}).keys())}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "13":
            ip = input(f"{Colors.CYAN}Enter IP address: {Colors.RESET}")
            results = self.transform.scanner.network_geo_lookup(ip)
            print(f"\n{Colors.GREEN}[+] Geo Location:{Colors.RESET}")
            for key, value in results.items():
                if value:
                    print(f"{Colors.YELLOW}  {key}: {Colors.WHITE}{value}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "14":
            url = input(f"{Colors.CYAN}Enter URL: {Colors.RESET}")
            results = self.transform.scanner.http_headers_analyze(url)
            print(f"\n{Colors.GREEN}[+] HTTP Headers:{Colors.RESET}")
            print(f"{Colors.YELLOW}  Status: {Colors.WHITE}{results.get('status_code', 'N/A')}{Colors.RESET}")
            print(f"{Colors.YELLOW}  Server: {Colors.WHITE}{results.get('server', 'N/A')}{Colors.RESET}")
            if results.get('security_headers'):
                print(f"{Colors.GREEN}  Security Headers:{Colors.RESET}")
                for header, value in results['security_headers'].items():
                    if value:
                        print(f"{Colors.YELLOW}    {header}: {Colors.WHITE}{value}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "15":
            filename = input(f"{Colors.CYAN}Enter filename (without extension): {Colors.RESET}")
            self.transform.graph.export_json(f"{filename}.json")
            print(f"\n{Colors.GREEN}[+] Exported to {filename}.json{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "16":
            filename = input(f"{Colors.CYAN}Enter filename (without extension): {Colors.RESET}")
            self.transform.report.generate_html_report(f"{filename}.html")
            self.transform.report.generate_csv_report(f"{filename}.csv")
            self.transform.report.generate_mtz_report(f"{filename}.mtz")
            print(f"\n{Colors.GREEN}[+] Reports generated:{Colors.RESET}")
            print(f"{Colors.GREEN}  - {filename}.html{Colors.RESET}")
            print(f"{Colors.GREEN}  - {filename}.csv{Colors.RESET}")
            print(f"{Colors.GREEN}  - {filename}.mtz{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "17":
            print(f"\n{Colors.GREEN}[+] Current Graph:{Colors.RESET}")
            print(f"{Colors.GREEN}  Entities: {Colors.WHITE}{len(self.transform.graph.entities)}{Colors.RESET}")
            print(f"{Colors.GREEN}  Links: {Colors.WHITE}{len(self.transform.graph.links)}{Colors.RESET}")
            print(f"\n{Colors.GREEN}  Sample entities:{Colors.RESET}")
            for entity in list(self.transform.graph.entities.values())[:10]:
                print(f"{Colors.YELLOW}    -> {Colors.WHITE}{entity.value} {Colors.DIM}({entity.type}){Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "18":
            stats = self.transform.graph.get_statistics()
            print(f"\n{Colors.GREEN}[+] Graph Statistics:{Colors.RESET}")
            print(f"{Colors.YELLOW}  Total entities: {Colors.WHITE}{stats['total_entities']}{Colors.RESET}")
            print(f"{Colors.YELLOW}  Total links: {Colors.WHITE}{stats['total_links']}{Colors.RESET}")
            print(f"{Colors.YELLOW}  Average connections: {Colors.WHITE}{stats['avg_connections']:.2f}{Colors.RESET}")
            print(f"\n{Colors.GREEN}  Entity types:{Colors.RESET}")
            for entity_type, count in stats['entity_types'].items():
                print(f"{Colors.YELLOW}    {entity_type}: {Colors.WHITE}{count}{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "19":
            query = input(f"{Colors.CYAN}Enter search query: {Colors.RESET}")
            results = self.transform.db.search_entities(query)
            print(f"\n{Colors.GREEN}[+] Found {len(results)} results:{Colors.RESET}")
            for row in results:
                print(f"{Colors.YELLOW}  -> {Colors.WHITE}{row[2]} {Colors.DIM}({row[1]}){Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "20":
            confirm = input(f"{Colors.RED}Clear all data? (y/n): {Colors.RESET}")
            if confirm.lower() == 'y':
                self.transform.graph = MaltegoGraph()
                self.transform.report = ReportGenerator(self.transform.graph)
                print(f"\n{Colors.GREEN}[+] Data cleared{Colors.RESET}")
            input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
        
        elif choice == "21":
            self.db_menu()
        
        elif choice == "22":
            self.batch_menu()
        
        elif choice == "0":
            print(f"\n{Colors.GREEN}[+] Exiting...{Colors.RESET}")
            self.running = False
    
    def db_menu(self):
        while True:
            self.clear_screen()
            print(f"{Colors.ORANGE}{'='*50}{Colors.RESET}")
            print(f"{Colors.ORANGE}      DATABASE MANAGEMENT{Colors.RESET}")
            print(f"{Colors.ORANGE}{'='*50}{Colors.RESET}")
            print(f"{Colors.YELLOW}[1]{Colors.RESET} View all entities")
            print(f"{Colors.YELLOW}[2]{Colors.RESET} View all links")
            print(f"{Colors.YELLOW}[3]{Colors.RESET} Search entities")
            print(f"{Colors.YELLOW}[4]{Colors.RESET} Export database")
            print(f"{Colors.YELLOW}[5]{Colors.RESET} Clear database")
            print(f"{Colors.RED}[0]{Colors.RESET} Back")
            print(f"{Colors.ORANGE}{'='*50}{Colors.RESET}")
            
            choice = input(f"{Colors.GREEN}Select option: {Colors.RESET}")
            
            if choice == "1":
                entities = self.transform.db.get_entities()
                print(f"\n{Colors.GREEN}[+] Total entities: {Colors.WHITE}{len(entities)}{Colors.RESET}")
                for row in entities[:20]:
                    print(f"{Colors.YELLOW}  {row[2]} {Colors.DIM}({row[1]}){Colors.RESET}")
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "2":
                conn = sqlite3.connect(self.transform.db.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM links LIMIT 20")
                links = cursor.fetchall()
                conn.close()
                print(f"\n{Colors.GREEN}[+] Total links: {Colors.WHITE}{len(links)}{Colors.RESET}")
                for link in links:
                    print(f"{Colors.YELLOW}  Link: {Colors.WHITE}{link[1]} -> {link[2]} {Colors.DIM}({link[3]}){Colors.RESET}")
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "5":
                confirm = input(f"{Colors.RED}Clear database? (y/n): {Colors.RESET}")
                if confirm.lower() == 'y':
                    os.remove(self.transform.db.db_path)
                    self.transform.db.init_db()
                    print(f"\n{Colors.GREEN}[+] Database cleared{Colors.RESET}")
                input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
            elif choice == "0":
                break
    
    def batch_menu(self):
        print(f"\n{Colors.GREEN}[+] Batch Scanning{Colors.RESET}")
        print(f"{Colors.YELLOW}[1]{Colors.RESET} Scan domains from file")
        print(f"{Colors.YELLOW}[2]{Colors.RESET} Scan IPs from file")
        print(f"{Colors.YELLOW}[3]{Colors.RESET} Scan emails from file")
        choice = input(f"{Colors.GREEN}Select: {Colors.RESET}")
        
        filename = input(f"{Colors.CYAN}Enter filename (one target per line): {Colors.RESET}")
        try:
            with open(filename, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            print(f"\n{Colors.GREEN}[+] Processing {len(targets)} targets...{Colors.RESET}")
            for i, target in enumerate(targets):
                print(f"{Colors.YELLOW}  [{i+1}/{len(targets)}] Processing {target}{Colors.RESET}")
                try:
                    if choice == "1":
                        self.transform.run_domain_intelligence(target)
                    elif choice == "2":
                        self.transform.run_ip_intelligence(target)
                    elif choice == "3":
                        self.transform.run_email_intelligence(target)
                except Exception as e:
                    print(f"{Colors.RED}  Error: {e}{Colors.RESET}")
            
            print(f"\n{Colors.GREEN}[+] Batch scan completed!{Colors.RESET}")
        except FileNotFoundError:
            print(f"\n{Colors.RED}[!] File not found: {filename}{Colors.RESET}")
        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")


def main():
    try:
        menu = MaltegoMenu()
        menu.main_menu()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)


if __name__ == "__main__":
    main()
