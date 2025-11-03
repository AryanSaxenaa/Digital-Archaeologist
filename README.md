# Digital Archaeologist

## Advanced Web Decay Forensics & Auto-Repair Engine

Digital Archaeologist is a sophisticated enterprise-grade web analysis tool designed to perform comprehensive website health audits, identify technical issues, and provide actionable insights for web optimization. Built with efficiency and accuracy in mind, this tool delivers professional-grade reporting in a compact, highly optimized codebase.

## Overview

Digital Archaeologist performs deep forensic analysis of websites to uncover hidden issues, performance bottlenecks, SEO problems, and security vulnerabilities. The tool crawls websites intelligently, respects robots.txt guidelines, and generates detailed reports that help website owners and developers maintain optimal web presence.

## Key Features

### Core Analysis Capabilities
- **Deep Link Analysis**: Comprehensive crawling with intelligent URL discovery from sitemaps and page links
- **SEO Health Scoring**: Automated audit with 100-point scoring system covering titles, meta descriptions, headings, and alt text
- **Security Vulnerability Scanning**: Detection of missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- **Performance Metrics**: Precise load time measurement with performance grading (A-F scale)
- **Content Freshness Analysis**: Multi-method detection of last-modified dates from headers and meta tags
- **Broken Link Detection**: Comprehensive 404/error detection with soft-404 intelligence
- **Mixed Content Detection**: Identification of insecure HTTP resources on HTTPS pages

### Advanced Features
- **Wayback Machine Integration**: Automatic archive.org fallback URLs for broken pages
- **Robots.txt Compliance**: Full parsing and respect for crawl directives and delays
- **Smart Caching System**: MD5-keyed file caching with configurable TTL (default 24h)
- **Multi-format Reporting**: JSON (technical), HTML (comprehensive), and structured summaries
- **Real-time Progress Tracking**: Optional TUI with tqdm progress bars and live statistics
- **JavaScript Rendering**: Optional support for dynamic content analysis (configurable)
- **Sitemap Discovery**: Automatic detection and parsing of XML sitemaps and sitemap indexes
- **Redirect Chain Analysis**: Tracking and reporting of redirect sequences
- **Content Analysis**: Word count, content length, and structural analysis
- **Intelligent Batching**: Async processing with configurable concurrent connection limits

### Reporting & Output
- **Professional HTML Reports**: Clean, responsive reports with technical details and summary grades
- **User-Friendly Summaries**: Plain English explanations with actionable recommendations
- **Technical JSON Output**: Complete technical data suitable for integration and further analysis
- **Actionable Recommendations**: Prioritized, specific action items for improvement
- **Grade-Based Scoring**: Letter grades (A-F) for Health, Performance, SEO, and Security
- **Historical Tracking**: Timestamped reports for trend analysis and improvement tracking

## X-Factors & Technical Excellence

### Architectural Efficiency
- **Ultra-Compact Design**: Enterprise functionality in just ~604 lines of code
- **Single-Loop Architecture**: Efficient async processing with minimal complexity
- **Memory Optimized**: Smart caching and data structures for large-scale analysis
- **Concurrent Processing**: Async/await pattern for maximum throughput

### Performance Optimizations
- **Rate Limiting**: Configurable politeness delays to respect server resources
- **Intelligent Batching**: Processes multiple URLs concurrently while maintaining control
- **Cache Intelligence**: Automatic cache invalidation and TTL management
- **Resource Management**: Proper connection pooling and cleanup

### Professional Standards
- **Enterprise-Grade Accuracy**: Rigorous testing and validation of all metrics
- **Comprehensive Error Handling**: Graceful degradation and detailed error reporting
- **Standards Compliance**: Follows web standards and best practices
- **Extensible Design**: Modular architecture for easy customization and extension

## Technical Constraints & Design Philosophy

### Code Efficiency Constraints
- **Optimized Codebase**: Enterprise functionality in approximately 600 lines of highly efficient Python
- **Single Loop Design**: Core processing logic uses one primary async loop for simplicity and performance
- **Minimal Dependencies**: Carefully selected dependencies (aiohttp, BeautifulSoup, httpx, aiofiles, PyYAML, tqdm)
- **Memory Conscious**: Designed to handle large websites without memory bloat using smart batching

### Performance Constraints
- **Politeness First**: Configurable delays (default 0.5s) to respect server resources
- **Intelligent Timeout Management**: 15-second default timeout with graceful error handling
- **Adaptive Rate Limiting**: Default 10 concurrent connections with intelligent batching
- **Resource Cleanup**: Proper async session and connection management with TCPConnector

### Advanced Features Implementation
- **Smart Cache System**: File-based caching with TTL (24-hour default) and MD5 key generation
- **Wayback Machine Integration**: Automatic archive.org fallback for broken pages
- **Robots.txt Parser**: Full compliance with robots.txt directives and crawl-delay
- **Sitemap Discovery**: Automatic XML sitemap detection and URL extraction
- **Soft 404 Detection**: Intelligent detection of pages that return 200 but contain error content
- **Security Headers Analysis**: Comprehensive check for HSTS, CSP, X-Frame-Options, etc.
- **SEO Scoring Algorithm**: Advanced scoring based on title, meta description, headings, and alt text
- **Content Freshness Detection**: Multiple methods for detecting last-modified dates

## Installation & Requirements

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Required Dependencies
```bash
# Install from requirements.txt (recommended)
pip install -r requirements.txt

# Or install manually:
pip install aiohttp>=3.8.0 beautifulsoup4>=4.11.0 httpx>=0.24.0 aiofiles>=0.8.0 PyYAML>=6.0 tqdm>=4.64.0
```

### Quick Install
```bash
# Clone or download the project
git clone <repository-url>
cd DigitalARCHAEOLOGIST

# Install dependencies
pip install -r requirements.txt

# Run your first analysis
python digitalarchaeologist.py https://example.com --tui
```

## Usage Guide

### Basic Usage
```bash
# Simple website analysis
python digitalarchaeologist.py https://example.com

# Analysis with progress display
python digitalarchaeologist.py https://example.com --tui

# Enable JavaScript rendering
python digitalarchaeologist.py https://example.com --js

# Limit analysis scope
python digitalarchaeologist.py https://example.com --max-pages 50 --depth 2
```

### Advanced Options
```bash
# Custom configuration
python digitalarchaeologist.py https://example.com --config custom_config.yaml

# Disable caching
python digitalarchaeologist.py https://example.com --no-cache

# CI/CD integration
python digitalarchaeologist.py https://example.com --github-action

# Email and Slack notifications
python digitalarchaeologist.py https://example.com --email user@domain.com --slack https://hooks.slack.com/webhook
```

### Command Line Arguments
- `url`: Target website URL (required)
- `--config`: Path to custom configuration file
- `--tui`: Enable interactive progress display
- `--github-action`: CI/CD mode for automated environments
- `--no-cache`: Disable intelligent caching
- `--js`: Enable JavaScript rendering for dynamic content
- `--depth`: Maximum crawl depth (default: 3)
- `--max-pages`: Maximum pages to analyze (default: 500)
- `--email`: Send report to specified email address
- `--slack`: Post results to Slack webhook URL

## Configuration

### Default Configuration
The tool includes intelligent defaults optimized for most use cases:
```yaml
max_depth: 3              # Maximum crawl depth
politeness_delay: 0.5     # Seconds between requests
stale_years: 1.5          # Years before content considered stale
timeout: 15               # Request timeout in seconds
user_agent: "DigitalArchaeologist (+https://github.com/archaeologist)"
cache_ttl: 86400          # Cache time-to-live (24 hours)
archive_fallback: true    # Enable Wayback Machine integration
js_render: false          # JavaScript rendering (requires additional setup)
robots_respect: true      # Respect robots.txt directives
rate_limit: 10            # Concurrent connections
security_scan: true       # Enable security vulnerability scanning
performance_metrics: true # Collect performance data
content_analysis: true    # Analyze content structure
seo_audit: true          # Perform SEO analysis
redirect_chains: true    # Track redirect sequences
image_analysis: true     # Analyze images and alt text
max_pages: 500           # Maximum pages to analyze
```

### Custom Configuration
Create `archaeologist.yaml` in the project directory to override defaults:
```yaml
# Example custom configuration
max_depth: 5
politeness_delay: 1.0
stale_years: 2.0
timeout: 20
max_pages: 1000
rate_limit: 5
user_agent: "MyCustomBot 1.0"
cache_ttl: 3600          # 1 hour cache
archive_fallback: false  # Disable Wayback Machine
robots_respect: true     # Always respect robots.txt
```

### Environment-Specific Configurations
```yaml
# High-performance configuration (for powerful servers)
rate_limit: 20
politeness_delay: 0.1
timeout: 10
max_pages: 2000

# Conservative configuration (for shared hosting or sensitive sites)
rate_limit: 3
politeness_delay: 2.0
timeout: 30
max_pages: 100
```

## Output & Reports

### Generated Files
The tool creates three types of reports in the `archaeologist_reports/` directory:

1. **HTML Report** (`website_report_domain_timestamp.html`)
   - Comprehensive visual report with all findings
   - Professional formatting suitable for stakeholders
   - Complete technical data in tabular format
   - Responsive design for desktop and mobile viewing

2. **User-Friendly Summary** (`website_health_report_domain_timestamp.json`)
   - Plain English explanations with actionable insights
   - Letter grades (A-F) for key metrics
   - Prioritized action items with specific recommendations
   - Executive summary format perfect for stakeholders

3. **Technical Analysis** (`technical_analysis_domain_timestamp.json`)
   - Raw technical data for each analyzed page
   - Detailed metrics including load times, SEO scores, security issues
   - Integration-ready JSON format for automated processing
   - Complete link graphs and redirect chain analysis

### Example Output Structure
```
archaeologist_reports/
├── website_report_example.com_20241103_230326.html
├── website_health_report_example.com_20241103_230326.json
└── technical_analysis_example.com_20241103_230326.json

.archaeologist_cache/  # Automatic caching directory
├── abc123def456.json
└── 789ghi012jkl.json
```

### Report Metrics & Scoring
- **Overall Health Score**: Composite score (0-100) based on broken links, performance, and freshness
- **Performance Grade**: Load time analysis with thresholds (A: <1s, B: <2s, C: <3s, D: <5s, F: >5s)
- **SEO Grade**: Search optimization score based on titles, descriptions, headings, and alt text
- **Security Grade**: Vulnerability assessment covering security headers and mixed content
- **Content Freshness**: Age analysis flagging content older than configurable threshold (default: 1.5 years)

## Use Cases

### Website Owners
- Regular health monitoring
- Pre-launch quality assurance
- SEO optimization guidance
- Security vulnerability assessment

### Developers
- Technical debt identification
- Performance optimization
- Integration testing
- Code quality metrics

### Agencies & Consultants
- Client reporting
- Competitive analysis
- Audit documentation
- Improvement roadmaps

### DevOps Teams
- CI/CD integration
- Automated monitoring
- Performance regression detection
- Security compliance checking

## Best Practices

### Analysis Strategy
1. Start with default settings for initial assessment
2. Use `--tui` for interactive monitoring of large sites
3. Enable `--js` only when analyzing dynamic content
4. Adjust `--max-pages` based on site size and analysis needs

### Performance Considerations
- Increase `politeness_delay` for sensitive or slow servers
- Use `--no-cache` for fresh analysis of frequently changing content
- Limit `max_pages` for initial exploratory analysis
- Monitor target server load during analysis

### Report Usage
- Share HTML reports with non-technical stakeholders
- Use JSON reports for technical teams and integration
- Reference user-friendly summaries for quick status updates
- Archive reports for historical comparison and trend analysis

## Troubleshooting

### Common Issues
- **Timeout Errors**: Increase timeout value in configuration
- **Rate Limiting**: Reduce concurrent connections or increase delays
- **Memory Usage**: Limit max_pages for very large websites
- **JavaScript Content**: Enable `--js` flag for dynamic sites

### Error Handling
The tool includes comprehensive error handling and will continue analysis even when individual pages fail. Check the console output and generated reports for specific error details.

## Technical Architecture

### Async Processing
Built on Python's asyncio framework for efficient concurrent processing while maintaining respect for target servers through intelligent rate limiting and politeness delays.

### Modular Design
- **Core Engine**: Website crawling and analysis
- **Report Generators**: Multiple output formats
- **Cache System**: Intelligent caching with TTL
- **Security Scanner**: Vulnerability detection
- **SEO Analyzer**: Search optimization audit

### Data Flow
1. URL validation and robots.txt parsing
2. Sitemap discovery and initial queue building
3. Concurrent page analysis with rate limiting
4. Data aggregation and scoring
5. Multi-format report generation

## Contributing

This project maintains high standards for code quality and efficiency. Contributions should:
- Preserve the compact design philosophy
- Maintain the single-loop architecture
- Include comprehensive error handling
- Follow existing code style and patterns

## License

Professional use license. Contact the development team for commercial licensing terms.

## Support

For technical support, feature requests, or integration assistance, please refer to the project documentation or contact the Digital Archaeology Team.

---

**Digital Archaeologist** - Uncovering the hidden truths of the modern web, one site at a time.