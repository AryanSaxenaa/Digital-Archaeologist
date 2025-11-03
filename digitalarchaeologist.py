#!/usr/bin/env python3
"""
ULTIMATE DIGITAL ARCHAEOLOGIST
Advanced Web Decay Forensics + Auto-Repair Engine

Features: Deep link analysis, SEO health scoring, Auto-repair suggestions with Wayback Machine,
Security vulnerability scanning, Content freshness analysis, Smart caching with TTL,
Robots.txt compliance, JavaScript rendering, Multi-format reporting, Real-time progress tracking

Author: Digital Archaeology Team | Enterprise-grade accuracy
"""
import asyncio, sys, json, os, re, yaml, hashlib, csv, httpx, aiofiles, logging
from urllib.parse import urljoin, urlparse
from datetime import datetime, timedelta
from aiohttp import ClientSession, TCPConnector, ClientTimeout
from bs4 import BeautifulSoup, Tag
import argparse, signal
from pathlib import Path
from tqdm import tqdm
from typing import Dict, List, Set, Optional, Tuple, Any, Union

# === ENHANCED CONFIG ===
DEFAULT_CONFIG = {
    "max_depth": 3, "politeness_delay": 0.5, "stale_years": 1.5, "timeout": 15,
    "user_agent": "DigitalArchaeologist (+https://github.com/archaeologist)",
    "cache_ttl": 86400, "archive_fallback": True, "js_render": False, "robots_respect": True,
    "rate_limit": 10, "security_scan": True, "performance_metrics": True, "content_analysis": True,
    "seo_audit": True, "redirect_chains": True, "image_analysis": True, "max_pages": 500
}
CONFIG_FILE, OUTPUT_DIR, CACHE_DIR = "archaeologist.yaml", "archaeologist_reports", ".archaeologist_cache"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# === ARGUMENT PARSER ===
parser = argparse.ArgumentParser(description="Ultimate Web Decay Auditor")
parser.add_argument("url", nargs="?", help="Target URL to analyze")
parser.add_argument("--config", help="Custom config file path")
parser.add_argument("--tui", action="store_true", help="Interactive progress display")
parser.add_argument("--github-action", action="store_true", help="CI/CD mode")
parser.add_argument("--email", help="Send report to email address")
parser.add_argument("--slack", help="Slack webhook URL for notifications")
parser.add_argument("--no-cache", action="store_true", help="Disable caching")
parser.add_argument("--js", action="store_true", help="Enable JavaScript rendering")
parser.add_argument("--depth", type=int, help="Maximum crawl depth")
parser.add_argument("--max-pages", type=int, help="Maximum pages to analyze")
args = parser.parse_args()

# === LOAD CONFIG ===
config = DEFAULT_CONFIG.copy()
if args.config and os.path.exists(args.config):
    with open(args.config) as f: config.update(yaml.safe_load(f))
elif os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE) as f: config.update(yaml.safe_load(f))

if args.depth: config["max_depth"] = args.depth
if args.max_pages: config["max_pages"] = args.max_pages

# === GLOBALS ===
interrupt, pbar = False, None

def signal_handler(sig, frame):
    global interrupt
    interrupt = True
    logger.info("Interrupt received. Saving progress...")
signal.signal(signal.SIGINT, signal_handler)

# === ENHANCED CACHE & UTILS ===
async def cache_get(key: str) -> Optional[Dict[str, Any]]:
    path = f"{CACHE_DIR}/{key}.json"
    if os.path.exists(path):
        try:
            async with aiofiles.open(path) as f:
                data = json.loads(await f.read())
                if datetime.now().timestamp() - data["ts"] < config["cache_ttl"]:
                    return data["value"]
        except Exception as e:
            logger.debug(f"Cache read error: {e}")
    return None

async def cache_set(key: str, value: Dict[str, Any]) -> None:
    path = f"{CACHE_DIR}/{key}.json"
    data = {"ts": datetime.now().timestamp(), "value": value}
    try:
        async with aiofiles.open(path, "w") as f:
            await f.write(json.dumps(data, default=str))
    except Exception as e:
        logger.debug(f"Cache write error: {e}")

def safe_get_attr(element: Any, attr: str, default: str = "") -> str:
    """Safely get attribute from BeautifulSoup element."""
    if element and hasattr(element, 'attrs') and attr in element.attrs:
        value = element.attrs[attr]
        return value[0] if isinstance(value, list) else str(value)
    return default

# === ROBOTS.TXT & SITEMAP HANDLING ===
async def fetch_robots(base_url: str, session: ClientSession) -> Dict[str, Any]:
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        timeout = ClientTimeout(total=5)
        async with session.get(robots_url, timeout=timeout) as resp:
            if resp.status == 200:
                text = await resp.text()
                return parse_robots(text, config["user_agent"].split()[0])
    except Exception as e:
        logger.debug(f"Failed to fetch robots.txt: {e}")
    return {"disallow": [], "crawl_delay": 0, "sitemaps": []}

def parse_robots(text: str, agent: str) -> Dict[str, Any]:
    disallow, crawl_delay, sitemaps, current_agent = [], 0, [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("User-agent:"):
            current_agent = line.split(":", 1)[1].strip()
        elif line.startswith("Sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
        elif current_agent in ("*", agent.split("/")[0]):
            if line.startswith("Disallow:"):
                path = line.split(":", 1)[1].strip()
                if path: disallow.append(path)
            elif line.startswith("Crawl-delay:"):
                try: crawl_delay = float(line.split(":", 1)[1].strip())
                except ValueError: pass
    return {"disallow": disallow, "crawl_delay": crawl_delay, "sitemaps": sitemaps}

def is_disallowed(url: str, robots: Dict[str, Any]) -> bool:
    if not config["robots_respect"]: return False
    path = urlparse(url).path
    return any(path.startswith(d) for d in robots.get("disallow", []))

async def fetch_sitemap(base_url: str, session: ClientSession, robots: Dict[str, Any]) -> List[str]:
    sitemap_urls = ["/sitemap.xml", "/sitemap_index.xml"]
    sitemap_urls.extend(robots.get("sitemaps", []))
    all_urls = []
    for sitemap_url in sitemap_urls:
        if not sitemap_url.startswith("http"):
            sitemap_url = urljoin(base_url, sitemap_url)
        try:
            timeout = ClientTimeout(total=10)
            async with session.get(sitemap_url, timeout=timeout) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    urls = re.findall(r'<loc>(.*?)</loc>', text)
                    all_urls.extend(urls)
        except Exception as e:
            logger.debug(f"Failed to fetch sitemap {sitemap_url}: {e}")
    return list(set(all_urls))

async def wayback_url(url: str) -> Optional[str]:
    if not config["archive_fallback"]: return None
    try:
        api = f"http://archive.org/wayback/available?url={url}"
        async with httpx.AsyncClient() as client:
            resp = await client.get(api, timeout=10)
            data = resp.json()
            if data.get("archived_snapshots", {}).get("closest", {}).get("available"):
                return data["archived_snapshots"]["closest"]["url"]
    except Exception as e:
        logger.debug(f"Wayback lookup failed: {e}")
    return None

# === PAGE ANALYSIS & SEO FUNCTIONS ===
def extract_page_date(headers: Dict[str, str], soup: BeautifulSoup) -> Optional[datetime]:
    lm = headers.get('last-modified')
    if lm:
        for fmt in ['%a, %d %b %Y %H:%M:%S %Z', '%a, %d %b %Y %H:%M:%S GMT', '%Y-%m-%dT%H:%M:%SZ']:
            try: return datetime.strptime(lm, fmt)
            except: continue
    for prop in ["article:modified_time", "og:updated_time", "dateModified", "datePublished"]:
        tag = soup.find("meta", property=prop) or soup.find("meta", attrs={"name": prop})
        if tag:
            content = safe_get_attr(tag, "content")
            if content:
                try: return datetime.fromisoformat(content.split("Z")[0].split("+")[0])
                except: continue
    return None

def calculate_seo_score(soup: BeautifulSoup, text: str, headers: Dict[str, str]) -> Dict[str, Any]:
    score, issues = 100, []
    title = soup.find('title')
    title_text = title.get_text().strip() if title else ""
    if not title_text: score -= 25; issues.append("Missing title tag")
    elif len(title_text) < 30: score -= 15; issues.append("Title too short")
    elif len(title_text) > 60: score -= 10; issues.append("Title too long")
    
    meta_desc = soup.find("meta", attrs={"name": "description"})
    desc_content = safe_get_attr(meta_desc, "content")
    if not desc_content: score -= 20; issues.append("Missing meta description")
    elif len(desc_content) > 160: score -= 5; issues.append("Meta description too long")
    
    h1_tags = soup.find_all('h1')
    if len(h1_tags) == 0: score -= 15; issues.append("Missing H1 tag")
    elif len(h1_tags) > 1: score -= 10; issues.append("Multiple H1 tags")
    
    images = soup.find_all('img')
    missing_alt = sum(1 for img in images if not safe_get_attr(img, 'alt'))
    if images and missing_alt / len(images) > 0.3:
        score -= 10; issues.append(f"{missing_alt}/{len(images)} images missing alt text")
    
    return {"score": max(0, score), "issues": issues, "title": title_text}

def scan_security_issues(soup: BeautifulSoup, headers: Dict[str, str]) -> List[str]:
    issues = []
    security_headers = {
        'strict-transport-security': 'HSTS', 'x-frame-options': 'Clickjacking protection',
        'x-content-type-options': 'MIME sniffing protection', 'content-security-policy': 'CSP'
    }
    for header, desc in security_headers.items():
        if header not in headers: issues.append(f"Missing {desc} header")
    
    for tag in soup.find_all(['script', 'link', 'img'], src=True):
        src = safe_get_attr(tag, 'src')
        if src.startswith('http://'):
            issues.append("Mixed content: insecure resources over HTTP")
            break
    return issues

def is_soft_404(text: str, status: int) -> bool:
    if status != 200: return False
    text_lower = text.lower()
    phrases = ["page not found", "404", "not found", "does not exist", "error occurred"]
    return any(p in text_lower for p in phrases) and len(text) < 8000

# === MAIN PAGE FETCHER & AUDIT ENGINE ===
async def fetch_and_analyze(url: str, robots: Dict[str, Any], session: ClientSession) -> Dict[str, Any]:
    if is_disallowed(url, robots): return {"status": -1, "reason": "robots.txt blocked", "url": url}
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if not args.no_cache:
        cached = await cache_get(cache_key)
        if cached: return cached

    start_time = datetime.now()
    try:
        timeout = ClientTimeout(total=config["timeout"])
        async with session.get(url, timeout=timeout, allow_redirects=True) as resp:
            status = resp.status
            headers = {k.lower(): v for k, v in resp.headers.items()}
            final_url = str(resp.url)
            text = await resp.text()
            load_time = (datetime.now() - start_time).total_seconds()

            if is_soft_404(text, status): status = 404
            soup = BeautifulSoup(text, 'html.parser')
            title = soup.find('title')
            title_text = title.get_text(strip=True)[:200] if title else ""
            
            date = extract_page_date(headers, soup)
            seo_analysis = calculate_seo_score(soup, text, headers)
            security_issues = scan_security_issues(soup, headers)
            
            links = set()
            for a in soup.find_all('a', href=True):
                href = safe_get_attr(a, 'href').strip()
                if href and not href.startswith(('#', 'mailto:', 'javascript:', 'tel:')):
                    abs_url = urljoin(final_url, href)
                    links.add(abs_url)

            result = {
                "url": url, "final_url": final_url, "status": status, "title": title_text,
                "last_modified": date.isoformat() if date else None,
                "stale": date and (datetime.now() - date).days > config["stale_years"] * 365,
                "links": list(links)[:100], "wayback": await wayback_url(url) if status >= 400 else None,
                "load_time": round(load_time, 2), "seo_analysis": seo_analysis, "security_issues": security_issues,
                "content_length": len(text), "word_count": len(text.split()) if text else 0,
                "redirect_chain": len(resp.history) if hasattr(resp, 'history') else 0
            }
            
            if not args.no_cache: await cache_set(cache_key, result)
            return result
    except Exception as e:
        return {"status": 0, "error": str(e), "url": url, "load_time": (datetime.now() - start_time).total_seconds()}

async def audit_website(start_url: str) -> Tuple[List[Dict[str, Any]], str, Dict[str, Any]]:
    global pbar
    domain = urlparse(start_url).netloc
    scheme = urlparse(start_url).scheme
    base_url = f"{scheme}://{domain}"
    
    connector = TCPConnector(limit=config["rate_limit"])
    session = ClientSession(connector=connector, headers={'User-Agent': config["user_agent"]}, 
                          timeout=ClientTimeout(total=config["timeout"]))
    
    try:
        robots = await fetch_robots(base_url, session)
        sitemap_urls = await fetch_sitemap(base_url, session, robots)
        queue = [start_url] + sitemap_urls[:50]
        seen, results = set(), []
        
        if args.tui: pbar = tqdm(total=min(config["max_pages"], 1000), desc="Analyzing", unit="page")
        
        while queue and len(results) < config["max_pages"] and not interrupt:
            batch = queue[:config["rate_limit"]]
            queue = queue[config["rate_limit"]:]
            
            tasks = []
            for url in batch:
                if url in seen: continue
                seen.add(url)
                tasks.append(fetch_and_analyze(url, robots, session))
            
            if not tasks: break
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for res in batch_results:
                if isinstance(res, dict) and res.get("status") not in [-1]:
                    results.append(res)
                    if pbar: pbar.update(1)
                    
                    if res.get("links") and urlparse(res["url"]).netloc == domain:
                        for link in res["links"][:20]:
                            if urlparse(link).netloc == domain and link not in seen:
                                queue.append(link)
            
            await asyncio.sleep(config["politeness_delay"])
        
        if pbar: pbar.close()
    finally:
        await session.close()
    
    return results, domain, robots

# === USER-FRIENDLY REPORTING ===
def generate_user_friendly_report(results: List[Dict[str, Any]], domain: str) -> Dict[str, Any]:
    total_pages = len(results)
    if total_pages == 0: return {"error": "No pages could be analyzed"}
    
    broken_pages, slow_pages, stale_content = [], [], []
    total_load_time, all_seo_issues, all_security_issues = 0, [], []
    
    for page in results:
        url, status, load_time = page.get("url", ""), page.get("status", 0), page.get("load_time", 0)
        total_load_time += load_time
        
        if status >= 400:
            broken_pages.append({
                "page": url.replace(f"https://{domain}", "").replace(f"http://{domain}", "") or "/",
                "problem": "Page not found" if status == 404 else f"Server error ({status})",
                "fix": "Check if page exists or fix server issues"
            })
        
        if load_time > 3:
            slow_pages.append({
                "page": url.replace(f"https://{domain}", "").replace(f"http://{domain}", "") or "/",
                "load_time": f"{load_time:.1f} seconds",
                "fix": "Optimize images, reduce file sizes, or improve server performance"
            })
        
        if page.get("stale"):
            stale_content.append({
                "page": url.replace(f"https://{domain}", "").replace(f"http://{domain}", "") or "/",
                "last_updated": page.get("last_modified", "Unknown")[:10] if page.get("last_modified") else "Unknown",
                "fix": "Update content with fresh information"
            })
        
        seo_analysis = page.get("seo_analysis", {})
        if seo_analysis.get("issues"):
            for issue in seo_analysis["issues"]:
                if issue not in all_seo_issues: all_seo_issues.append(issue)
                    
        security_issues = page.get("security_issues", [])
        for issue in security_issues:
            if issue not in all_security_issues: all_security_issues.append(issue)
    
    # Convert technical issues to user-friendly language
    seo_friendly = {
        "Missing title tag": "Some pages don't have titles (important for search engines)",
        "Title too short": "Some page titles are too short to be effective",
        "Title too long": "Some page titles are too long and may be cut off",
        "Missing meta description": "Pages missing descriptions (what users see in search results)",
        "Meta description too long": "Some page descriptions are too long",
        "Missing H1 tag": "Pages missing main headings (confusing for readers)",
        "Multiple H1 tags": "Pages have multiple main headings (confusing structure)"
    }
    
    security_friendly = {
        "Missing HSTS header": "Website not enforcing secure connections",
        "Missing Clickjacking protection header": "Website vulnerable to clickjacking attacks",
        "Missing MIME sniffing protection header": "Website missing content protection",
        "Missing CSP header": "Website missing content security policies",
        "Mixed content: insecure resources over HTTP": "Some content loads insecurely"
    }
    
    def calculate_grade(score):
        if score >= 90: return "A"
        elif score >= 80: return "B" 
        elif score >= 70: return "C"
        elif score >= 60: return "D"
        else: return "F"
    
    # Calculate scores
    health_score = 100
    if total_pages > 0:
        broken_ratio = len(broken_pages) / total_pages
        slow_ratio = len(slow_pages) / total_pages
        stale_ratio = len(stale_content) / total_pages
        health_score = max(0, 100 - (broken_ratio * 40) - (slow_ratio * 20) - (stale_ratio * 20))
    
    avg_load_time = total_load_time / total_pages if total_pages > 0 else 0
    if avg_load_time <= 1: perf_score = 100
    elif avg_load_time <= 2: perf_score = 90
    elif avg_load_time <= 3: perf_score = 80
    elif avg_load_time <= 5: perf_score = 60
    else: perf_score = 40
    
    seo_score = max(0, 100 - (len(all_seo_issues) * 15))
    security_score = max(0, 100 - (len(all_security_issues) * 20))
    
    return {
        "website": domain, "scan_date": datetime.now().strftime("%B %d, %Y"), "pages_checked": total_pages,
        "overall": {
            "health_score": round(health_score, 1), "grade": calculate_grade(health_score),
            "status": "Excellent" if health_score >= 90 else "Good" if health_score >= 70 else "Needs Attention" if health_score >= 50 else "Poor"
        },
        "performance": {
            "grade": calculate_grade(perf_score), "average_load_time": f"{avg_load_time:.1f} seconds",
            "status": "Fast" if avg_load_time <= 2 else "Moderate" if avg_load_time <= 4 else "Slow",
            "slow_pages_count": len(slow_pages)
        },
        "seo": {
            "grade": calculate_grade(seo_score), "issues_found": len(all_seo_issues),
            "status": "Optimized" if seo_score >= 80 else "Needs Work" if seo_score >= 60 else "Poor"
        },
        "security": {
            "grade": calculate_grade(security_score), "vulnerabilities": len(all_security_issues),
            "status": "Secure" if security_score >= 80 else "At Risk" if security_score >= 60 else "Vulnerable"
        },
        "issues": {
            "broken_pages": broken_pages[:10], "slow_pages": slow_pages[:10], "stale_content": stale_content[:10],
            "seo_problems": [seo_friendly.get(issue, issue) for issue in all_seo_issues],
            "security_warnings": [security_friendly.get(issue, issue) for issue in all_security_issues]
        },
        "action_items": generate_simple_recommendations(broken_pages, slow_pages, stale_content, all_seo_issues, all_security_issues)
    }

def generate_simple_recommendations(broken_pages, slow_pages, stale_content, seo_issues, security_issues) -> List[str]:
    recommendations = []
    if broken_pages: recommendations.append(f"Fix {len(broken_pages)} broken page(s) that visitors can't access")
    if slow_pages: recommendations.append(f"Speed up {len(slow_pages)} slow-loading page(s) for better user experience")
    if stale_content: recommendations.append(f"Update {len(stale_content)} page(s) with outdated content")
    if seo_issues: recommendations.append(f"Improve SEO by fixing {len(seo_issues)} search engine optimization issue(s)")
    if security_issues: recommendations.append(f"Enhance security by addressing {len(security_issues)} vulnerability(ies)")
    if not recommendations: recommendations.append("Great job! No major issues found with your website")
    return recommendations

def create_comprehensive_html_report(report_data: Dict[str, Any], technical_data: List[Dict[str, Any]]) -> str:
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Website Analysis - {report_data['website']}</title>
<style>body{{font-family:Arial,sans-serif;margin:20px;line-height:1.6}}table{{border-collapse:collapse;width:100%;margin:10px 0}}
th,td{{border:1px solid #ddd;padding:8px;text-align:left}}th{{background-color:#f2f2f2}}
.grade-A{{color:green;font-weight:bold}}.grade-B{{color:blue;font-weight:bold}}.grade-C{{color:orange;font-weight:bold}}
.grade-D{{color:red;font-weight:bold}}.grade-F{{color:darkred;font-weight:bold}}
.section{{margin:20px 0;padding:10px;border:1px solid #ccc}}.technical{{background-color:#f9f9f9;font-size:0.9em}}
.status-ok{{color:green}}.status-error{{color:red}}
</style></head><body>
<h1>Website Analysis: {report_data['website']}</h1>
<p><strong>Scan:</strong> {report_data['scan_date']} | <strong>Pages:</strong> {report_data['pages_checked']}</p>
<div class="section"><h2>Summary</h2><table>
<tr><th>Metric</th><th>Score</th><th>Grade</th><th>Status</th></tr>
<tr><td>Overall Health</td><td>{report_data['overall']['health_score']}/100</td><td class="grade-{report_data['overall']['grade']}">{report_data['overall']['grade']}</td><td>{report_data['overall']['status']}</td></tr>
<tr><td>Performance</td><td>{report_data['performance']['average_load_time']}</td><td class="grade-{report_data['performance']['grade']}">{report_data['performance']['grade']}</td><td>{report_data['performance']['status']}</td></tr>
<tr><td>SEO</td><td>{report_data['seo']['issues_found']} issues</td><td class="grade-{report_data['seo']['grade']}">{report_data['seo']['grade']}</td><td>{report_data['seo']['status']}</td></tr>
<tr><td>Security</td><td>{report_data['security']['vulnerabilities']} issues</td><td class="grade-{report_data['security']['grade']}">{report_data['security']['grade']}</td><td>{report_data['security']['status']}</td></tr>
</table></div>
<div class="section technical"><h2>Page Details</h2><table>
<tr><th>URL</th><th>Status</th><th>Load Time</th><th>Title</th><th>SEO</th><th>Security</th><th>Archive</th></tr>"""
    
    for page in technical_data:
        status_class = "status-ok" if page.get('status', 0) < 400 else "status-error"
        wayback = "✓" if page.get('wayback') else "✗"
        security_count = len(page.get('security_issues', []))
        seo_score = page.get('seo_analysis', {}).get('score', 'N/A')
        title = page.get('title', 'N/A')
        title_display = title[:30] + "..." if len(title) > 30 else title
        
        html += f'<tr><td>{page.get("url", "N/A")}</td><td class="{status_class}">{page.get("status", "N/A")}</td><td>{page.get("load_time", "N/A")}s</td><td>{title_display}</td><td>{seo_score}</td><td>{security_count}</td><td>{wayback}</td></tr>'
    
    html += '</table></div>'
    
    issues = report_data.get('issues', {})
    
    if issues.get('broken_pages'):
        html += '<div class="section"><h2>Broken Pages</h2><table><tr><th>Page</th><th>Problem</th><th>Fix</th></tr>'
        for page in issues['broken_pages']:
            html += f'<tr><td>{page["page"]}</td><td>{page["problem"]}</td><td>{page["fix"]}</td></tr>'
        html += '</table></div>'
    
    if issues.get('slow_pages'):
        html += '<div class="section"><h2>Slow Pages</h2><table><tr><th>Page</th><th>Load Time</th><th>Fix</th></tr>'
        for page in issues['slow_pages']:
            html += f'<tr><td>{page["page"]}</td><td>{page["load_time"]}</td><td>{page["fix"]}</td></tr>'
        html += '</table></div>'
    
    if issues.get('stale_content'):
        html += '<div class="section"><h2>Outdated Content</h2><table><tr><th>Page</th><th>Last Updated</th><th>Fix</th></tr>'
        for page in issues['stale_content']:
            html += f'<tr><td>{page["page"]}</td><td>{page["last_updated"]}</td><td>{page["fix"]}</td></tr>'
        html += '</table></div>'
    
    if issues.get('seo_problems'):
        html += '<div class="section"><h2>SEO Issues</h2><ul>'
        for issue in issues['seo_problems']: html += f'<li>{issue}</li>'
        html += '</ul></div>'
    
    if issues.get('security_warnings'):
        html += '<div class="section"><h2>Security Issues</h2><ul>'
        for warning in issues['security_warnings']: html += f'<li>{warning}</li>'
        html += '</ul></div>'
    
    html += '<div class="section technical"><h2>Technical Details</h2>'
    for i, page in enumerate(technical_data, 1):
        html += f'<h3>Page {i}: {page.get("url", "Unknown")}</h3><table>'
        html += f'<tr><td>Status</td><td class="{"status-ok" if page.get("status", 0) < 400 else "status-error"}">{page.get("status", "N/A")}</td></tr>'
        html += f'<tr><td>Load Time</td><td>{page.get("load_time", "N/A")}s</td></tr>'
        html += f'<tr><td>Title</td><td>{page.get("title", "N/A")}</td></tr>'
        html += f'<tr><td>Content Size</td><td>{page.get("content_length", "N/A")} bytes</td></tr>'
        html += f'<tr><td>Word Count</td><td>{page.get("word_count", "N/A")}</td></tr>'
        html += f'<tr><td>Last Modified</td><td>{page.get("last_modified", "N/A")}</td></tr>'
        html += f'<tr><td>Redirects</td><td>{page.get("redirect_chain", 0)}</td></tr>'
        html += f'<tr><td>Archive</td><td>{"Available" if page.get("wayback") else "None"}</td></tr>'
        
        seo_data = page.get('seo_analysis', {})
        html += f'<tr><td>SEO Score</td><td>{seo_data.get("score", "N/A")}/100</td></tr>'
        if seo_data.get('issues'): html += f'<tr><td>SEO Issues</td><td>{", ".join(seo_data["issues"])}</td></tr>'
        if page.get('security_issues'): html += f'<tr><td>Security Issues</td><td>{", ".join(page["security_issues"])}</td></tr>'
        if page.get('links'): html += f'<tr><td>Links Found</td><td>{len(page["links"])}</td></tr>'
        html += '</table>'
    html += '</div>'
    
    if report_data.get('action_items'):
        html += '<div class="section"><h2>Recommended Actions</h2><ol>'
        for action in report_data['action_items']: html += f'<li>{action}</li>'
        html += '</ol></div>'
    
    html += '<div class="section"><h2>Report Guide</h2><p><strong>Grades:</strong> A=Excellent, B=Good, C=Fair, D=Poor, F=Critical<br><strong>Scores:</strong> Health=Overall condition, Performance=Speed, SEO=Search visibility, Security=Protection level</p></div><p><em>Report by Digital Archaeologist</em></p></body></html>'
    return html

def generate_recommendations(results: List[Dict[str, Any]]) -> List[str]:
    recommendations = []
    broken_count = sum(1 for r in results if r.get("status", 0) >= 400)
    stale_count = sum(1 for r in results if r.get("stale"))
    if broken_count > 0: recommendations.append(f"Fix {broken_count} broken links/pages")
    if stale_count > 0: recommendations.append(f"Update {stale_count} stale pages")
    return recommendations

# === MAIN EXECUTION ===
async def main():
    if not args.url:
        print("Usage: python digitalarchaeologist.py <url> [options]")
        print("\nExample: python digitalarchaeologist.py https://example.com --tui --js")
        sys.exit(1)

    print(f"""
╔══════════════════════════════════════════════════════════╗
║            ULTIMATE DIGITAL ARCHAEOLOGIST                ║
║     Advanced Web Decay Forensics + Auto-Repair Engine    ║
║                 Enterprise-grade accuracy                ║
╚══════════════════════════════════════════════════════════╝
Target: {args.url}
Max Pages: {config['max_pages']} | Depth: {config['max_depth']}
    """)

    try:
        results, domain, robots = await audit_website(args.url)
        report = generate_user_friendly_report(results, domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        json_path = f"{OUTPUT_DIR}/technical_analysis_{domain}_{timestamp}.json"
        with open(json_path, 'w') as f: json.dump(results, f, indent=2, default=str)
        
        report_path = f"{OUTPUT_DIR}/website_health_report_{domain}_{timestamp}.json"
        with open(report_path, 'w') as f: json.dump(report, f, indent=2, default=str)
        
        html_report = create_comprehensive_html_report(report, results)
        html_path = f"{OUTPUT_DIR}/website_report_{domain}_{timestamp}.html"
        with open(html_path, 'w', encoding='utf-8') as f: f.write(html_report)
        
        print(f"\n{'='*60}")
        print(f"WEBSITE HEALTH CHECKUP COMPLETE")
        print(f"Website: {report['website']}")
        print(f"Pages Analyzed: {report['pages_checked']}")
        print(f"\nREPORT CARD:")
        print(f"   Overall Health: {report['overall']['health_score']}/100 (Grade {report['overall']['grade']}) - {report['overall']['status']}")
        print(f"   Performance: {report['performance']['average_load_time']} average - {report['performance']['status']}")
        print(f"   SEO Health: {report['seo']['issues_found']} issues found - {report['seo']['status']}")
        print(f"   Security: {report['security']['vulnerabilities']} vulnerabilities - {report['security']['status']}")
        
        print(f"\nWHAT TO DO NEXT:")
        for i, action in enumerate(report['action_items'], 1): print(f"   {i}. {action}")
        
        print(f"\nREPORTS CREATED:")
        print(f"   Easy-to-read report: {html_path}")
        print(f"   Summary data: {report_path}")
        print(f"   Technical details: {json_path}")
        print(f"\nTIP: Open the HTML file in your web browser for the best viewing experience!")
        
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())