# app.py — Final Webyverse Domain Analyzer (Full Feature Set)

import os
import ssl
import socket
import logging
import json
import requests
import dns.resolver
import whois
import urllib3
import re
import matplotlib.pyplot as plt  # For graphing (ensure you have this installed)
import re
import socket
import smtplib
import time
import concurrent.futures 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import phonenumbers
import pytz
import threading
import subprocess
import json
import re
from phonenumbers import geocoder, carrier, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from werkzeug.middleware.proxy_fix import ProxyFix  # If you plan reverse proxy usage
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template, send_file
from ipwhois import IPWhois
from urllib.parse import urlparse, urljoin
from datetime import datetime
from io import BytesIO
from datetime import datetime, timedelta
import concurrent.futures 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import builtwith
except ImportError:
    builtwith = None

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://google.com/"
}

HOSTING_API = "https://ipapi.is/json/?ip={ip}"
HOSTING_TIMEOUT = 3  # Seconds per IP check

# RapidAPI credentials for SimilarWeb Traffic API
RAPIDAPI_KEY = "4d71b40c05mshbc6cb40c5ce3e9ap15b370jsna22da9bc486c"
RAPIDAPI_HOST = "similarweb-traffic.p.rapidapi.com"

def make_session(retries=3, backoff=1.0):
    session = requests.Session()
    retry = requests.adapters.Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[403, 429, 500, 502, 503, 504]
    )
    if hasattr(retry, 'allowed_methods'):
        retry.allowed_methods = frozenset(['HEAD', 'GET'])
    else:
        retry.method_whitelist = frozenset(['HEAD', 'GET'])
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def fetch_url(url, method='get', timeout=15, headers=None, verify=True):
    hdrs = headers or DEFAULT_HEADERS
    sess = make_session()
    try:
        if method.lower() == 'head':
            return sess.head(url, timeout=timeout, headers=hdrs,
                             allow_redirects=True, verify=verify)
        return sess.get(url, timeout=timeout, headers=hdrs,
                        allow_redirects=True, verify=verify)
    except Exception:
        if verify:
            return fetch_url(url, method, timeout, headers, False)
        return None

def normalize_domain_input(domain_input):
    """Enhanced domain input normalization to handle all formats"""
    if not domain_input:
        return None

    domain_input = domain_input.strip()

    # If it already has a scheme, extract the domain part
    if domain_input.startswith(('http://', 'https://')):
        parsed = urlparse(domain_input)
        domain = parsed.netloc
        # Remove www. if present
        domain = re.sub(r'^www\.', '', domain, flags=re.IGNORECASE)
        return domain

    # Remove www. prefix if present
    domain_input = re.sub(r'^www\.', '', domain_input, flags=re.IGNORECASE)

    # If it's just a plain domain, return as is
    if '.' in domain_input:
        return domain_input

    return domain_input

def prepare_url(domain):
    """Enhanced URL preparation with better domain handling"""
    # First normalize the input
    domain = normalize_domain_input(domain)
    if not domain:
        return None, None

    # Try different URL variants (keep existing logic but use normalized domain)
    variants = [
        f"https://{domain}",
        f"https://www.{domain}",
        f"http://{domain}",
        f"http://www.{domain}"
    ]

    for url in variants:
        for method in ('head', 'get'):
            resp = fetch_url(url, method=method)
            if resp and resp.status_code < 400:
                return resp.url, resp.headers
    return None, None

def detect_cms(soup):
    if not soup:
        return 'Unknown'
    html = str(soup).lower()
    patterns = {
        'wordpress': 'WordPress', 'wp-content': 'WordPress',
        'shopify': 'Shopify', 'wix': 'Wix',
        'drupal': 'Drupal', 'joomla': 'Joomla',
        'magento': 'Magento', 'squarespace': 'Squarespace',
        'webflow': 'Webflow', 'ghost': 'Ghost', 'typo3': 'TYPO3'
    }
    for key, name in patterns.items():
        if key in html:
            return name
    meta = soup.find('meta', attrs={'name':'generator'})
    if meta and meta.get('content'):
        cont = meta['content'].lower()
        for key, name in patterns.items():
            if key in cont:
                return name
    return 'Unknown'
    
def get_hosting_provider_info(ip):
    """Enhanced hosting provider detection with multiple APIs"""
    try:
        # Try multiple APIs for better coverage
        apis = [
            f"https://ipapi.co/{ip}/json/",
            f"https://ipinfo.io/{ip}/json",
            HOSTING_API.format(ip=ip)
        ]

        for api_url in apis:
            try:
                resp = requests.get(api_url, timeout=HOSTING_TIMEOUT)
                if resp.status_code == 200:
                    data = resp.json()

                    # Parse different API responses
                    if 'ipapi.co' in api_url:
                        return {
                            'provider': data.get('org', ''),
                            'asn': data.get('asn', ''),
                            'country': data.get('country_name', ''),
                            'city': data.get('city', ''),
                            'is_datacenter': 'hosting' in data.get('org', '').lower() or 'server' in data.get('org', '').lower()
                        }
                    elif 'ipinfo.io' in api_url:
                        return {
                            'provider': data.get('org', ''),
                            'asn': data.get('org', '').split()[0] if data.get('org') else '',
                            'country': data.get('country', ''),
                            'city': data.get('city', ''),
                            'is_datacenter': 'hosting' in data.get('org', '').lower() or 'AS' in data.get('org', '')
                        }
                    else:  # ipapi.is
                        return {
                            'provider': data.get('company', {}).get('name', ''),
                            'asn': data.get('asn', {}).get('number', ''),
                            'country': data.get('location', {}).get('country', ''),
                            'city': data.get('location', {}).get('city', ''),
                            'is_datacenter': data.get('is_datacenter', False)
                        }
            except Exception:
                continue
    except Exception as e:
        logging.error(f"Hosting provider lookup error for {ip}: {str(e)}")

    return {
        'provider': 'Unknown',
        'asn': 'Unknown',
        'country': 'Unknown',
        'city': 'Unknown',
        'is_datacenter': False
    }
def get_shared_hosting_domains(ip):
    """Get domains sharing the same IP (reverse IP lookup)"""
    try:
        # Using HackerTarget API for reverse IP lookup
        api_url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"

        resp = requests.get(api_url, timeout=5)
        if resp.status_code == 200:
            domains = resp.text.strip().split('\n')
            # Filter out error messages and clean domains
            domains = [d.strip() for d in domains if d.strip() and not d.startswith('error') and not d.startswith('API')]
            return domains[:20]  # Limit to 20 domains

    except Exception as e:
        logging.error(f"Shared hosting lookup error for {ip}: {str(e)}")

    return []
    
    
def validate_email_format(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def check_mx_record(domain):
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        mx_list = [str(mx.exchange).rstrip('.') for mx in mx_records]
        return True, mx_list
    except Exception:
        return False, []

def check_smtp_connection(email, timeout=10):
    domain = email.split('@')[1]
    try:
        has_mx, mx_records = check_mx_record(domain)
        if not has_mx or not mx_records:
            return False, "No valid MX records found", None
        primary_mx = mx_records[0]
        server = smtplib.SMTP(timeout=timeout)
        code, message = server.connect(primary_mx, 25)
        if code == 220:
            server.helo()
            server.quit()
            return True, f"SMTP server {primary_mx} reachable", primary_mx
        else:
            return False, f"SMTP connection failed with code {code}", primary_mx
    except Exception as e:
        return False, f"SMTP check error: {str(e)}", None

def check_disposable_email(email):
    disposable_domains = [
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com', 'mailinator.com',
        'yopmail.com', 'temp-mail.org', 'sharklasers.com', 'maildrop.cc',
        'getnada.com', 'grr.la', 'trashmail.com'
    ]
    domain = email.split('@')[1].lower()
    return domain in disposable_domains

def find_associated_domain(email):
    domain = email.split('@')[1]
    common_providers = ['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','icloud.com','protonmail.com']
    if domain.lower() in common_providers:
        return None, "Generic email provider"
    # Try to check if domain has a website
    urls = [f'https://{domain}', f'https://www.{domain}']
    for url in urls:
        resp = fetch_url(url, method='head', timeout=5)
        if resp and resp.status_code < 400:
            return domain, "Custom domain with website"
    return domain, "Custom domain (no website detected)"

def get_ip_info(domain):
    """Enhanced IP information with comprehensive hosting detection"""
    records = []
    try:
        # Use normalized domain
        host = normalize_domain_input(domain)
        if not host:
            return records

        # Resolve IPs
        try:
            answers = dns.resolver.resolve(host, 'A')
            ips = [a.to_text() for a in answers]
        except Exception as dns_error:
            logging.error(f"DNS resolution failed for {host}: {str(dns_error)}")
            return [{'error': f'DNS resolution failed: {str(dns_error)}'}]

        for ip in ips:
            try:
                # Get hosting provider info
                hosting_info = get_hosting_provider_info(ip)

                # Get WHOIS data
                try:
                    rd = IPWhois(ip).lookup_rdap(depth=1)
                except Exception as whois_error:
                    rd = {}

                # Get reverse DNS
                try:
                    hostname, _, _ = socket.gethostbyaddr(ip)
                except:
                    hostname = 'Unknown'

                # Determine if IP is shared or dedicated
                is_shared = hosting_info['is_datacenter'] or 'hosting' in hosting_info['provider'].lower()

                # Get shared domains if it's a shared IP
                shared_domains = []
                if is_shared:
                    shared_domains = get_shared_hosting_domains(ip)

                record = {
                    'ip': ip,
                    'hostname': hostname,
                    'hosting_type': 'Shared' if is_shared else 'Dedicated',
                    'hosting_provider': hosting_info['provider'],
                    'hosting_country': hosting_info['country'],
                    'hosting_city': hosting_info['city'],
                    'asn': hosting_info['asn'] or rd.get('asn'),
                    'asn_description': rd.get('asn_description', ''),
                    'network_name': rd.get('network', {}).get('name', ''),
                    'shared_domains': shared_domains,
                    'shared_domains_count': len(shared_domains),
                    'is_datacenter': hosting_info['is_datacenter']
                }

                records.append(record)

            except Exception as e:
                logging.error(f"Error processing IP {ip}: {str(e)}")
                records.append({
                    'ip': ip,
                    'hostname': 'Unknown',
                    'hosting_type': 'Unknown',
                    'error': str(e)
                })

    except Exception as e:
        logging.error(f"IP info error: {str(e)}")
        records.append({'error': str(e)})

    return records
    
def get_ssl_info(domain):
    try:
        host = urlparse(domain).netloc if domain.startswith(('http://','https://')) else domain
        host = host.lstrip('www.')
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            issuer = dict(x[0] for x in cert.get('issuer',[])).get('O','Unknown')
            not_after = cert.get('notAfter')
            try:
                expires = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').strftime('%Y-%m-%d')
            except Exception:
                expires = not_after
            return {'issuer': issuer, 'expires': expires,
                    'serial': cert.get('serialNumber'), 'version': cert.get('version')}
    except Exception:
        return None

def get_dns_records(domain):
    d=domain.lstrip('www.')
    out={}
    for rt in ('A','MX','NS','TXT'):
        try:
            out[rt]=[r.to_text() for r in dns.resolver.resolve(d,rt)]
        except Exception:
            out[rt]=[]
    return out

def get_whois_summary(domain):
    dom=urlparse(domain).netloc if domain.startswith(('http://','https://')) else domain
    dom=dom.lstrip('www.')
    try:
        w=whois.whois(dom)
        def fmt(d):
            if not d: return None
            if isinstance(d,list): d=d[0]
            return d.strftime('%Y-%m-%d') if hasattr(d,'strftime') else str(d)
        return {
            'domain_name': w.domain_name,
            'registrar': w.registrar,
            'creation_date': fmt(w.creation_date),
            'expiration_date': fmt(w.expiration_date),
            'updated_date': fmt(w.updated_date),
            'name_servers': w.name_servers or []
        }
    except Exception:
        return {}

def get_robots_sitemap(url):
    if not url:
        return {'robots_txt': False, 'sitemap_xml': False, 'sitemap_urls': []}
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    res = {'robots_txt': False, 'sitemap_xml': False, 'sitemap_urls': []}
    r = fetch_url(base+'/robots.txt')
    if r and r.status_code==200:
        res['robots_txt']=True
        for ln in r.text.splitlines():
            if ln.lower().startswith('sitemap:'):
                sm=ln.split(':',1)[1].strip()
                res['sitemap_xml']=True
                res['sitemap_urls'].append(sm)
    return res

def get_open_graph(soup):
    if not soup: return {}
    og={}
    for prop in ['title','description','image','url','type','site_name','locale','app_id']:
        m=soup.find('meta', property=f'og:{prop}')
        if m and m.get('content'): og[prop]=m['content']
    tw={}
    for prop in ['card','site','title','description','image']:
        m=soup.find('meta', attrs={'name':f'twitter:{prop}'})
        if m and m.get('content'): tw[prop]=m['content']
    if tw: og['twitter_card']=tw
    return og

def find_social(soup):
    if not soup: return []
    pats=['facebook.com','twitter.com','linkedin.com','instagram.com',
          'youtube.com','pinterest.com','tiktok.com','github.com','medium.com']
    links=set()
    for a in soup.find_all('a', href=True):
        href=a['href']
        for p in pats:
            if p in href.lower():
                if href.startswith('//'): href='https:'+href
                if href.startswith(('http://','https://')): links.add(href)
    return sorted(links)

def detect_language(soup):
    if not soup: return None
    try:
        lang = soup.html.get('lang') or soup.find('meta', attrs={'http-equiv':'content-language'})
        if lang and hasattr(lang, 'get'):
            return lang.get('content')
        elif lang:
            return lang
    except Exception:
        pass
    try:
        alt=soup.find('link', rel='alternate', hreflang=True)
        return alt['hreflang'] if alt and alt.get('hreflang') else None
    except Exception:
        return None

def find_favicon(soup, base):
    if not soup: return None
    try:
        for rel in ['icon','shortcut icon','apple-touch-icon']:
            l=soup.find('link', rel=lambda r: r and rel in r.lower())
            if l and l.get('href'): return urljoin(base, l['href'])
        for p in ['/favicon.ico','/favicon.png','/apple-touch-icon.png']:
            r=fetch_url(base+p, method='head')
            if r and r.status_code==200: return base+p
    except Exception: pass
    return None
    
def get_hosting_type(ip):
    """Determine if IP belongs to hosting provider/datacenter"""
    try:
        resp = requests.get(HOSTING_API.format(ip=ip), timeout=HOSTING_TIMEOUT)
        if resp.status_code == 200:
            data = resp.json()
            return {
                'is_hosting': data.get('is_datacenter', False),
                'hosting_provider': data.get('datacenter', {}).get('name'),
                'hosting_network': data.get('network'),
                'hosting_domain': data.get('datacenter', {}).get('domain')
            }
    except Exception as e:
        logging.error(f"Hosting API error for {ip}: {str(e)}")
    return {'is_hosting': False}

def detect_tech_stack(soup, response, url):
    tech={'Frameworks':[],'Server':[],'Analytics':[],'JS Libraries':[]}
    if builtwith:
        try: 
            tech_data = builtwith.parse(url)
            return tech_data if tech_data else tech
        except Exception: pass
    html=str(soup).lower() if soup else ''
    hdrs=response.headers if response else {}
    if 'server' in hdrs: tech['Server'].append(hdrs['server'])
    fw={'wordpress':'WordPress','shopify':'Shopify','wix':'Wix','drupal':'Drupal'}
    for k,v in fw.items():
        if k in html and v not in tech['Frameworks']: tech['Frameworks'].append(v)
    return tech
    
def get_traffic_data(domain, period):
    """
    Fetches traffic data using the SimilarWeb Traffic RapidAPI.
    The 'period' parameter is currently illustrative as the API might not support it directly.
    """
    url = "https://similarweb-traffic.p.rapidapi.com/traffic"
    querystring = {"domain": domain}
    headers = {
        "x-rapidapi-key": RAPIDAPI_KEY,
        "x-rapidapi-host": RAPIDAPI_HOST
    }

    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()

        # Parse the API response to fit the expected structure
        # This is a simplified mapping based on typical SimilarWeb data
        total_page_views = data.get('visits', 0) * 1000000 # Assuming 'visits' is in millions
        unique_views = int(total_page_views * 0.8) # Placeholder for unique views
        
        # Extracting top countries
        countries_data = {}
        if 'traffic_by_country' in data and isinstance(data['traffic_by_country'], list):
            for entry in data['traffic_by_country']:
                country_name = entry.get('country', 'Unknown')
                traffic_share = entry.get('value', 0) # This is a percentage share
                countries_data[country_name] = int(total_page_views * (traffic_share / 100)) # Convert share to absolute visits

        # Placeholder for orders and historical data as SimilarWeb API might not provide this directly
        orders = {
            'hour': int(total_page_views / (30 * 24 * 60 / 5)), # Example: 5 orders per hour
            'day': int(total_page_views / 30),
            'month': int(total_page_views)
        }

        # Placeholder for historical data (you'd need a more advanced API or logic for this)
        historical_data = {
            'monthly': {
                '2024-01': {'page_views': total_page_views * 0.9, 'unique_visitors': unique_views * 0.9, 'bounce_rate': 0.5},
                '2024-02': {'page_views': total_page_views * 0.95, 'unique_visitors': unique_views * 0.95, 'bounce_rate': 0.48},
                '2024-03': {'page_views': total_page_views, 'unique_visitors': unique_views, 'bounce_rate': 0.45},
            },
            'quarterly': {
                'Q1-2024': {'page_views': total_page_views * 2.8, 'unique_visitors': unique_views * 2.8, 'bounce_rate': 0.47},
            },
            'yearly': {
                '2023': {'page_views': total_page_views * 10, 'unique_visitors': unique_views * 10, 'bounce_rate': 0.52},
            }
        }


        return {
            'total_page_views': total_page_views,
            'unique_views': unique_views,
            'countries': countries_data,
            'orders': orders,
            'historical_data': historical_data # Add historical data
        }

    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching traffic data for {domain}: {e}")
        return {
            'total_page_views': 0,
            'unique_views': 0,
            'countries': {},
            'orders': {},
            'historical_data': {}
        }
    except Exception as e:
        logging.error(f"Unexpected error processing traffic data for {domain}: {e}")
        return {
            'total_page_views': 0,
            'unique_views': 0,
            'countries': {},
            'orders': {},
            'historical_data': {}
        }

def get_ecommerce_and_plugins(domain):
    # Placeholder for e-commerce and plugins detection logic
    ecommerce_data = {
        'platform': 'Shopify',
        'plugins': ['Plugin1', 'Plugin2', 'Plugin3']
    }
    return ecommerce_data
    

def calculate_scores(data):
    # SEO Score (unchanged)
    seo = 0
    if data.get('meta_tags'): seo += 40
    if data.get('open_graph'): seo += 30
    if data.get('language'): seo += 10
    if data.get('robots_sitemap', {}).get('sitemap_xml'): seo += 20

    # Security Score (unchanged)
    security = 0
    if data.get('ssl_info'): security += 50
    security += len(data.get('security_headers', {})) * 10

    # Enhanced Performance Score
    performance = 0
    
    # Base score for successful connection
    if data.get('base_url'):
        performance += 20
    
    # Check for performance-related headers
    headers = data.get('headers', {})
    
    # Compression (gzip/brotli)
    if any(encoding in headers.get('Content-Encoding', '').lower() 
           for encoding in ['gzip', 'br', 'deflate']):
        performance += 15
    
    # Caching headers
    cache_headers = ['Cache-Control', 'ETag', 'Last-Modified', 'Expires']
    cache_score = sum(5 for header in cache_headers if header in headers)
    performance += min(cache_score, 20)
    
    # Content-Type optimization
    content_type = headers.get('Content-Type', '').lower()
    if 'text/html' in content_type:
        performance += 10
    
    # Server response efficiency
    server = headers.get('Server', '').lower()
    if any(fast_server in server for fast_server in ['nginx', 'cloudflare', 'apache']):
        performance += 10
    
    # CDN detection (basic)
    if any(cdn in str(headers).lower() for cdn in ['cloudflare', 'fastly', 'cloudfront', 'maxcdn']):
        performance += 15
    
    # Technology stack efficiency
    tech_stack = data.get('tech_stack', {})
    if tech_stack:
        # Modern frameworks get bonus points
        frameworks = tech_stack.get('Frameworks', [])
        if any(modern in str(frameworks).lower() 
               for modern in ['react', 'vue', 'angular', 'next.js', 'nuxt']):
            performance += 10
    
    # Hosting quality (based on hosting info)
    hosting_info = data.get('hosting_info', [])
    if hosting_info and len(hosting_info) > 0:
        first_host = hosting_info[0]
        
        # Dedicated hosting gets bonus
        if first_host.get('hosting_type') == 'Dedicated':
            performance += 10
        
        # Known good hosting providers
        provider = first_host.get('hosting_provider', '').lower()
        good_providers = ['cloudflare', 'amazon', 'google', 'microsoft', 'digitalocean', 'linode']
        if any(good in provider for good in good_providers):
            performance += 10
    
    # SSL/HTTPS bonus (performance related)
    if data.get('ssl_info'):
        performance += 5
    
    # Penalty for missing critical elements
    if not data.get('title') or data.get('title') == '—':
        performance -= 5
    
    # Favicon presence (small performance indicator)
    if data.get('favicon_url'):
        performance += 5

    # Ensure minimum score
    performance = max(performance, 10)

    overall = round((seo + security + performance) / 3)
    return {
        'seo_score': min(seo, 100),
        'security_score': min(security, 100),
        'performance_score': min(performance, 100),
        'overall_score': min(overall, 100)
    }

# === Phone Lookup Functions ===

def parse_phone_number(phone_input):
    """Parse and validate phone number"""
    try:
        # Clean the input
        cleaned = re.sub(r'[^\d+]', '', phone_input.strip())
        
        # Try to parse with different country codes if no country code provided
        if not cleaned.startswith('+'):
            # Try common country codes
            for country_code in ['+1', '+44', '+91', '+86', '+33', '+49', '+81']:
                try:
                    test_number = country_code + cleaned
                    parsed = phonenumbers.parse(test_number, None)
                    if phonenumbers.is_valid_number(parsed):
                        return parsed, test_number
                except:
                    continue
            
            # If no country code works, try as US number
            try:
                parsed = phonenumbers.parse(cleaned, 'US')
                if phonenumbers.is_valid_number(parsed):
                    return parsed, phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            except:
                pass
        else:
            parsed = phonenumbers.parse(cleaned, None)
            if phonenumbers.is_valid_number(parsed):
                return parsed, cleaned
                
        return None, None
    except Exception as e:
        logging.error(f"Phone parsing error: {str(e)}")
        return None, None

def get_phone_basic_info(parsed_number, formatted_number):
    """Get basic phone number information"""
    try:
        info = {
            'formatted_international': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            'formatted_national': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL),
            'formatted_e164': phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164),
            'country_code': f"+{parsed_number.country_code}",
            'national_number': str(parsed_number.national_number),
            'country_name': geocoder.description_for_number(parsed_number, 'en'),
            'location': geocoder.description_for_number(parsed_number, 'en'),
            'carrier_name': carrier.name_for_number(parsed_number, 'en'),
            'line_type': 'Mobile' if carrier.name_for_number(parsed_number, 'en') else 'Landline',
            'is_valid': phonenumbers.is_valid_number(parsed_number),
            'is_possible': phonenumbers.is_possible_number(parsed_number)
        }
        
        # Get timezone information
        timezones = timezone.time_zones_for_number(parsed_number)
        if timezones:
            tz = pytz.timezone(timezones[0])
            current_time = datetime.now(tz)
            info['timezone'] = {
                'timezone_name': timezones[0],
                'current_time': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'utc_offset': current_time.strftime('%z'),
                'timezone_abbreviation': current_time.strftime('%Z')
            }
        else:
            info['timezone'] = None
            
        return info
    except Exception as e:
        logging.error(f"Basic info error: {str(e)}")
        return {}

def search_social_media_accounts(phone_number):
    """Search for social media accounts associated with phone number"""
    accounts = []
    
    try:
        # Search common platforms manually
        platforms = {
            'WhatsApp': f"https://wa.me/{phone_number.replace('+', '')}",
            'Telegram': f"https://t.me/{phone_number.replace('+', '')}",
            'Viber': f"viber://chat?number={phone_number.replace('+', '')}"
        }
        
        for platform, url in platforms.items():
            # Basic check if the platform might have this number
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                if resp.status_code < 400:
                    accounts.append({
                        'platform': platform,
                        'url': url,
                        'status': 'Possible Account',
                        'confidence': 'Medium'
                    })
            except:
                pass
                
    except Exception as e:
        logging.error(f"Social media search error: {str(e)}")
    
    return accounts

def search_data_breaches(phone_number):
    """Search for data breaches containing this phone number"""
    breaches = []
    
    try:
        # This would typically use Have I Been Pwned API
        # For now, we'll return a placeholder structure
        # You can implement actual API calls here
        
        # Placeholder data structure
        breach_info = {
            'total_breaches': 0,
            'breaches': [],
            'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        return breach_info
    except Exception as e:
        logging.error(f"Data breach search error: {str(e)}")
        return {'total_breaches': 0, 'breaches': [], 'last_checked': 'Error'}

def get_carrier_details(parsed_number):
    """Get detailed carrier information"""
    try:
        carrier_name = carrier.name_for_number(parsed_number, 'en')
        
        # Enhanced carrier detection
        carrier_info = {
            'name': carrier_name or 'Unknown',
            'type': 'Mobile' if carrier_name else 'Landline/Unknown',
            'country': geocoder.description_for_number(parsed_number, 'en'),
            'mcc_mnc': 'Unknown'  # Would need additional API for this
        }
        
        return carrier_info
    except Exception as e:
        logging.error(f"Carrier details error: {str(e)}")
        return {'name': 'Unknown', 'type': 'Unknown', 'country': 'Unknown'}

def reverse_phone_lookup(phone_number):
    """Perform reverse lookup to find associated information"""
    try:
        results = {
            'owner_info': {
                'name': 'Not Available',
                'address': 'Not Available',
                'email': 'Not Available'
            },
            'business_info': {
                'company_name': 'Not Available',
                'website': 'Not Available',
                'industry': 'Not Available'
            },
            'additional_numbers': [],
            'confidence_score': 0
        }
        
        # Here you would implement actual reverse lookup logic
        # using free APIs or databases
        
        return results
    except Exception as e:
        logging.error(f"Reverse lookup error: {str(e)}")
        return {
            'owner_info': {'name': 'Error', 'address': 'Error', 'email': 'Error'},
            'business_info': {'company_name': 'Error', 'website': 'Error', 'industry': 'Error'},
            'additional_numbers': [],
            'confidence_score': 0
        }

def calculate_phone_lookup_score(data):
    """Calculate overall lookup confidence score"""
    score = 0
    
    # Basic validation
    if data.get('basic_info', {}).get('is_valid'):
        score += 30
    
    # Carrier information
    if data.get('carrier_info', {}).get('name') != 'Unknown':
        score += 20
    
    # Location information
    if data.get('basic_info', {}).get('country_name'):
        score += 15
    
    # Social media accounts found
    if data.get('social_accounts'):
        score += len(data['social_accounts']) * 5
    
    # Timezone information
    if data.get('basic_info', {}).get('timezone'):
        score += 10
    
    # Cap at 100
    score = min(score, 100)
    
    return score

# === Flask Application Setup ===
app = Flask(__name__, static_folder='static', template_folder='templates')
logging.basicConfig(level=logging.INFO)
os.makedirs('data', exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/history')
def history():
    f = 'data/history.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return render_template('history.html', history=json.load(file))
    return render_template('history.html', history=[])

@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    d = request.form.get('domain', '').strip()
    if not d or '.' not in d:
        return jsonify(error='Invalid domain'), 400

    # Enhanced domain normalization
    normalized_domain = normalize_domain_input(d)
    if not normalized_domain:
        return jsonify(error='Invalid domain format'), 400

    base, headers = prepare_url(normalized_domain)
    if not base:
        return jsonify(error='Unable to fetch domain'), 500
    r = fetch_url(base)
    soup = BeautifulSoup(r.content, 'html.parser') if r else None

    meta_tags = {
        (m.get('name') or m.get('property') or 'meta'): m.get('content', '')
        for m in (soup.find_all('meta') if soup else [])
        if m.get('name') or m.get('property')
    }

    # Existing info dictionary
    info = {
        'domain': normalized_domain,
        'original_input': d,  # Keep track of original input
        'base_url': base,
        'title': soup.title.string.strip() if soup and soup.title else '—',
        'cms': detect_cms(soup),
        'hosting_info': get_ip_info(normalized_domain),
        'ssl_info': get_ssl_info(normalized_domain),
        'whois_info': get_whois_summary(normalized_domain),
        'dns_records': get_dns_records(normalized_domain),
        'robots_sitemap': get_robots_sitemap(base),
        'tech_stack': detect_tech_stack(soup, r, base),
        'social_links': find_social(soup),
        'open_graph': get_open_graph(soup),
        'meta_tags': meta_tags,
        'language': detect_language(soup) or '—',
        'favicon_url': find_favicon(soup, base),
        'headers': dict(headers or {}),
        'security_headers': get_security_headers(dict(headers or {})),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    # Calculate scores
    scores = calculate_scores(info)
    info.update(scores)

    # New: Get traffic data
    traffic_data = get_traffic_data(normalized_domain, 'month')  # You can adjust the period as needed
    info.update({
        'traffic_data': traffic_data
    })

    # New: Get e-commerce and plugins data
    ecommerce_data = get_ecommerce_and_plugins(normalized_domain)
    info.update({
        'ecommerce_data': ecommerce_data
    })

    # Save to history and domain file (use normalized domain for filename)
    histf = 'data/history.json'
    hist = []
    if os.path.exists(histf):
        with open(histf, 'r') as file:
            hist = json.load(file)
    hist = [item for item in hist if item.get('domain') != normalized_domain]
    hist.insert(0, {'domain': normalized_domain, 'timestamp': info['timestamp']})
    with open(histf, 'w') as file:
        json.dump(hist[:100], file)

    with open(f'data/{normalized_domain.replace(".", "_")}.json', 'w') as file:
        json.dump(info, file)

    return jsonify(info)

@app.route('/api/domains')
def api_domains():
    f = 'data/history.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return jsonify(json.load(file))
    return jsonify([])

@app.route('/api/domain/<name>')
def api_domain(name):
    f = f'data/{name.replace(".", "_")}.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return jsonify(json.load(file))
    return jsonify(error='Not found'), 404
    
@app.route('/api/export/<name>')
def api_export(name):
    f = f'data/{name.replace(".", "_")}.json'
    if not os.path.exists(f):
        return jsonify(error='File not found'), 404
    with open(f, 'r') as file:
        data = file.read()
    return send_file(BytesIO(data.encode('utf-8')),
                     download_name=f'{name}.json',
                     as_attachment=True,
                     mimetype='application/json')

@app.route('/api/clear-history', methods=['DELETE'])
def clear_history():
    try:
        # Clear history.json
        hist_file = 'data/history.json'
        if os.path.exists(hist_file):
            with open(hist_file, 'w') as f:
                json.dump([], f)
        
        # Optionally clear all domain files
        import glob
        for file in glob.glob('data/*.json'):
            if file != hist_file:
                os.remove(file)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
        
@app.route('/documentation')
def documentation():
    return render_template('documentation.html')



def get_security_headers(headers):
    targets = ['Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options',
               'Content-Security-Policy', 'Referrer-Policy', 'Permissions-Policy']
    return {h: headers[h] for h in targets if h in headers}
    
# Add this new route to your existing app.py file
@app.route('/verify-email', methods=['POST'])
def verify_email():
    email = request.form.get('email', '').strip().lower()
    if not email:
        return jsonify(error='Please provide an email address'), 400
    if not validate_email_format(email):
        return jsonify(error='Invalid email format'), 400

    try:
        start_time = time.time()
        info = {
            'email': email,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'format_valid': False,
        }

        score = 0
        issues = []

        if validate_email_format(email):
            info['format_valid'] = True
            score += 30
        else:
            issues.append('Invalid email format')

        if check_disposable_email(email):
            issues.append('Disposable email detected')
        else:
            score += 20

        domain = email.split('@')[1]

        # Check MX records
        has_mx, mx_records = check_mx_record(domain)
        info['mx_records'] = {'has_mx': has_mx, 'records': mx_records}
        if has_mx:
            score += 20
        else:
            issues.append('No MX records found')

        # Check SMTP connection
        smtp_valid, smtp_msg, smtp_server = check_smtp_connection(email)
        info['smtp_check'] = {'valid': smtp_valid, 'message': smtp_msg, 'server': smtp_server}
        if smtp_valid:
            score += 20
        else:
            issues.append('SMTP server unreachable')

        # Check associated domain and website presence
        associated_domain, domain_status = find_associated_domain(email)
        info['associated_domain'] = associated_domain
        info['domain_status'] = domain_status
        
        # New flag to control whether to show warning for domain
        show_domain_warning = False
        if domain_status == "Custom domain with website":
            # No domain-related issues
            show_domain_warning = False
            score += 10
        else:
            # Add domain warning issue
            issues.append('Custom domain without website or generic domain')
            show_domain_warning = True
        
        info['show_domain_warning'] = show_domain_warning


        # Cap score between 0 and 100
        score = max(0, min(100, score))

        # Determine deliverability from score and key checks
        if score >= 70 and smtp_valid and has_mx and info['format_valid']:
            deliverability_status = 'Deliverable'
        else:
            deliverability_status = 'Undeliverable'

        info['reputation_score'] = score
        info['issues'] = issues
        info['deliverability_status'] = deliverability_status
        info['is_disposable'] = check_disposable_email(email)

        # Save email verification result to a JSON file (use safe filename)
        safe_email = email.replace('@', '_at_').replace('.', '_')
        with open(f'data/email_{safe_email}.json', 'w') as f:
            json.dump(info, f, indent=2)

        # Add to email verification history
        hist_file = 'data/email_history.json'
        hist = []
        if os.path.exists(hist_file):
            with open(hist_file, 'r') as f:
                hist = json.load(f)
        hist = [item for item in hist if item.get('email') != email]
        hist.insert(0, {'email': email, 'timestamp': info['timestamp'], 'reputation_score': score})
        with open(hist_file, 'w') as f:
            json.dump(hist[:100], f, indent=2)

        info['analysis_duration'] = round(time.time() - start_time, 2)
        return jsonify(info)
    except Exception as e:
        return jsonify(error=str(e)), 500


        
@app.route('/api/emails')
def api_emails():
    f = 'data/email_history.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return jsonify(json.load(file))
    return jsonify([])

@app.route('/api/email/<path:email>')
def api_email(email):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    f = f'data/email_{safe_email}.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return jsonify(json.load(file))
    return jsonify(error='Email data not found'), 404

@app.route('/api/export-email/<path:email>')
def api_export_email(email):
    safe_email = email.replace('@', '_at_').replace('.', '_')
    f = f'data/email_{safe_email}.json'
    if not os.path.exists(f):
        return jsonify(error='File not found'), 404
    with open(f, 'r') as file:
        data = file.read()
    return send_file(BytesIO(data.encode('utf-8')),
                     download_name=f'email_verification_{email}.json',
                     as_attachment=True,
                     mimetype='application/json')

@app.route('/email-verify')
def email_verify_page():
    return render_template('email_verify.html')
    
@app.route('/email-docs')
def email_docs():
    """Email verification documentation page"""
    return render_template('emaildocs.html')

# Alternative route with different URL pattern (optional)
@app.route('/email-verify/docs')
def email_verify_docs():
    """Alternative URL for email verification documentation"""
    return render_template('emaildocs.html')

# Another alternative route (optional)
@app.route('/emaildocs')
def emaildocs_short():
    """Short URL for email verification documentation"""
    return render_template('emaildocs.html')

# === Phone Lookup Routes ===



@app.route('/phone-lookup')
def phone_lookup_page():
    """Phone lookup main page"""
    return render_template('phone_lookup.html')
    
@app.route('/phone-docs')
def phone_docs():
    """Phone lookup documentation page"""
    return render_template('phonedocs.html')
@app.route('/phonedocs')
def phone_docs_alt():
    """Phone lookup documentation page (alternative URL)"""
    return render_template('phonedocs.html')
    
@app.route('/phonehistory')
def phone_history_page():
    """Phone lookup history page"""
    return render_template('phonehistory.html')

@app.route('/lookup-phone', methods=['POST'])
def lookup_phone():
    """Main phone lookup endpoint"""
    phone_input = request.form.get('phone', '').strip()
    
    if not phone_input:
        return jsonify(error='Please provide a phone number'), 400
    
    try:
        start_time = time.time()
        
        # Parse phone number
        parsed_number, formatted_number = parse_phone_number(phone_input)
        
        if not parsed_number:
            return jsonify(error='Invalid phone number format'), 400
        
        # Gather all information
        info = {
            'phone_number': formatted_number,
            'original_input': phone_input,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        
        # Get basic phone information
        basic_info = get_phone_basic_info(parsed_number, formatted_number)
        info['basic_info'] = basic_info
        
        # Get carrier details
        carrier_info = get_carrier_details(parsed_number)
        info['carrier_info'] = carrier_info
        
        # Search social media accounts
        social_accounts = search_social_media_accounts(formatted_number)
        info['social_accounts'] = social_accounts
        
        # Search data breaches
        breach_info = search_data_breaches(formatted_number)
        info['breach_info'] = breach_info
        
        # Perform reverse lookup
        reverse_info = reverse_phone_lookup(formatted_number)
        info['reverse_lookup'] = reverse_info
        
        # Calculate confidence score
        confidence_score = calculate_phone_lookup_score(info)
        info['confidence_score'] = confidence_score
        
        # Analysis duration
        info['analysis_duration'] = round(time.time() - start_time, 2)
        
        # Save to history
        save_phone_lookup_history(formatted_number, info)
        
        return jsonify(info)
        
    except Exception as e:
        logging.error(f"Phone lookup error: {str(e)}")
        return jsonify(error=f'Lookup failed: {str(e)}'), 500

def save_phone_lookup_history(phone_number, info):
    """Save phone lookup to history"""
    try:
        # Save individual lookup
        safe_phone = phone_number.replace('+', 'plus_').replace(' ', '_')
        with open(f'data/phone_{safe_phone}.json', 'w') as f:
            json.dump(info, f, indent=2)
        
        # Update history
        hist_file = 'data/phone_history.json'
        hist = []
        if os.path.exists(hist_file):
            with open(hist_file, 'r') as f:
                hist = json.load(f)
        
        # Remove existing entry for this number
        hist = [item for item in hist if item.get('phone_number') != phone_number]
        
        # Add new entry
        hist.insert(0, {
            'phone_number': phone_number,
            'timestamp': info['timestamp'],
            'confidence_score': info.get('confidence_score', 0)
        })
        
        # Keep only last 100 entries
        with open(hist_file, 'w') as f:
            json.dump(hist[:100], f, indent=2)
            
    except Exception as e:
        logging.error(f"History save error: {str(e)}")

@app.route('/api/phone-history')
def api_phone_history():
    """Get phone lookup history"""
    f = 'data/phone_history.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return jsonify(json.load(file))
    return jsonify([])

@app.route('/api/phone/<path:phone>')
def api_phone_lookup(phone):
    """Get specific phone lookup data"""
    safe_phone = phone.replace('+', 'plus_').replace(' ', '_')
    f = f'data/phone_{safe_phone}.json'
    if os.path.exists(f):
        with open(f, 'r') as file:
            return jsonify(json.load(file))
    return jsonify(error='Phone lookup data not found'), 404

@app.route('/emailhistory')
def email_history_page():
    """Email verification history page"""
    return render_template('emailhistory.html')


# Alternative routes for email history (optional)
@app.route('/email-history') 
def email_history_alt():
    """Alternative URL for email verification history"""
    return render_template('emailhistory.html')

@app.route('/email-verify/history')
def email_verify_history():
    """Email verification history under email-verify path"""
    return render_template('emailhistory.html')
    
@app.route('/api/clear-email-history', methods=['DELETE'])
def clear_email_history():
    """Clear email verification history specifically"""
    try:
        # Clear email history.json
        email_hist_file = 'data/email_history.json'
        if os.path.exists(email_hist_file):
            with open(email_hist_file, 'w') as f:
                json.dump([], f)
        
        # Clear all email verification files
        import glob
        for file in glob.glob('data/email_*.json'):
            if file != email_hist_file and 'email_' in file:
                os.remove(file)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/analyze-domain/<domain>')
def analyze_domain(domain):
    # Redirect to your existing domain analyzer with prefilled domain query param
    return redirect(f'/?domain={domain}')


@app.route('/json-view/<domain>')
def json_view(domain):
    """Display domain data as formatted JSON in a web page"""
    f = f'data/{domain.replace(".", "_")}.json'
    if not os.path.exists(f):
        return render_template('json_view.html', 
                             domain=domain, 
                             json_data=None, 
                             error="Domain data not found")
    
    with open(f, 'r') as file:
        data = json.load(file)
    
    return render_template('json_view.html', 
                         domain=domain, 
                         json_data=json.dumps(data, indent=2),
                         error=None)

@app.route('/api/clear-phone-history', methods=['DELETE'])
def clear_phone_history():
    """Clear phone lookup history"""
    try:
        # Clear phone history
        phone_hist_file = 'data/phone_history.json'
        if os.path.exists(phone_hist_file):
            with open(phone_hist_file, 'w') as f:
                json.dump([], f)
        
        # Clear all phone lookup files
        import glob
        for file in glob.glob('data/phone_*.json'):
            if file != phone_hist_file and 'phone_' in file:
                os.remove(file)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/export-phone/<path:phone>')
def api_export_phone(phone):
    """Export phone lookup data as JSON file"""
    safe_phone = phone.replace('+', 'plus_').replace(' ', '_')
    f = f'data/phone_{safe_phone}.json'
    if not os.path.exists(f):
        return jsonify(error='File not found'), 404
    with open(f, 'r') as file:
        data = file.read()
    return send_file(BytesIO(data.encode('utf-8')),
                     download_name=f'phone_lookup_{phone}.json',
                     as_attachment=True,
                     mimetype='application/json')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=False)
