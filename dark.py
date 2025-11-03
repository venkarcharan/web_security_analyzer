import streamlit as st
import requests
import json
from urllib.parse import urlparse, urljoin
import pandas as pd
import plotly.graph_objects as go
from requests.exceptions import RequestException
import re
from huggingface_hub import InferenceClient
from bs4 import BeautifulSoup
import socket
import ssl
from typing import List, Dict

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Hugging Face API Token and Model
hf_api_token = "my-api-token"
repo_id = "mistralai/Mixtral-8x7B-Instruct-v0.1"

# Initialize Hugging Face Inference Client
llm_client = InferenceClient(
    model=repo_id,
    timeout=120,
    token=hf_api_token,
)

def call_llm(inference_client: InferenceClient, prompt: str):
    response = inference_client.post(
        json={
            "inputs": prompt,
            "parameters": {"max_new_tokens": 1000},
            "task": "text-generation",
        },
    )
    return json.loads(response.decode())[0]["generated_text"]

def check_sql_injection_vulnerability(url: str) -> List[str]:
    test_payloads = [
        "'", "1' OR '1'='1", "1; DROP TABLE users",
        "' OR '1'='1' --", "admin' --", "1' UNION SELECT NULL--"
    ]
    vulnerabilities = []
    
    try:
        for payload in test_payloads:
            test_url = f"{url}?id={payload}"
            response = requests.get(test_url, timeout=5)
            
            sql_errors = [
                "sql", "mysql", "sqlite", "postgresql", "oracle",
                "ORA-", "SQL syntax", "mysql_fetch", "SQL error"
            ]
            response_text = response.text.lower()
            
            if any(error in response_text for error in sql_errors):
                vulnerabilities.append(f"Potential SQL injection vulnerability found with payload: {payload}")
    except Exception as e:
        vulnerabilities.append(f"Could not complete SQL injection test: {str(e)}")
    
    return vulnerabilities

def check_xss_vulnerability(url: str) -> List[str]:
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')"
    ]
    vulnerabilities = []
    
    try:
        for payload in xss_payloads:
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url, timeout=5)
            
            if payload.lower() in response.text.lower():
                vulnerabilities.append(f"Potential XSS vulnerability found with payload: {payload}")
    except Exception as e:
        vulnerabilities.append(f"Could not complete XSS test: {str(e)}")
    
    return vulnerabilities

def check_open_ports(url: str) -> List[str]:
    vulnerabilities = []
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.split(':')[0]
    
    common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389]
    
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            if result == 0:
                vulnerabilities.append(f"Port {port} is open and potentially vulnerable")
            sock.close()
    except Exception as e:
        vulnerabilities.append(f"Could not complete port scan: {str(e)}")
    
    return vulnerabilities

def check_ssl_vulnerabilities(url: str) -> List[str]:
    vulnerabilities = []
    parsed_url = urlparse(url)
    hostname = parsed_url.netloc.split(':')[0]
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                if not cert:
                    vulnerabilities.append("Invalid SSL certificate")
                
                # Check SSL version
                if ssock.version() < ssl.TLSVersion.TLSv1_2:
                    vulnerabilities.append("Outdated SSL/TLS version detected")
    except Exception as e:
        vulnerabilities.append(f"SSL vulnerability check failed: {str(e)}")
    
    return vulnerabilities

def analyze_http_security(url: str) -> List[str]:
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        security_issues = []

        if not url.startswith('https'):
            security_issues.append("Website not using HTTPS")

        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking protection)',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header (MIME-type sniffing protection)',
            'Content-Security-Policy': 'Missing Content-Security-Policy header (XSS protection)',
            'Strict-Transport-Security': 'Missing HSTS header (forces HTTPS)',
            'X-XSS-Protection': 'Missing X-XSS-Protection header',
            'Referrer-Policy': 'Missing Referrer-Policy header'
        }

        for header, message in security_headers.items():
            if header not in headers:
                security_issues.append(message)

        return security_issues
    except Exception as e:
        return [f"Could not analyze HTTP security: {str(e)}"]

def check_dark_patterns(url: str, timeout: int = 10) -> List[str]:
    """
    Check a website for dark patterns by analyzing its content.
    
    Args:
        url (str): The URL to analyze
        timeout (int): Request timeout in seconds
        
    Returns:
        List[str]: List of detected dark patterns with their categories
    """
    try:
        # Setup headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Get both visible and hidden content
        content = soup.get_text().lower()
        dark_patterns = []
        
        patterns = {
            "Urgency": [
                "limited time", "ending soon", "only today", "last chance",
                "hurry", "don't miss out", "flash sale", "time running out",
                "expires", "countdown", "deadline", "act now", "offer ends",
                "sale ends", "closing soon", "final hours", "almost over",
                "time is running out", "ends at midnight", "today only",
                "few hours left", "ends soon", "act fast", "quick",
                "running out of time", "don't delay", "immediate"
            ],
            "Scarcity": [
                "only few left", "limited stock", "running out", "exclusive offer",
                "while supplies last", "limited edition", "rare find",
                "selling fast", "high demand", "almost gone", "low stock",
                "only '%' left", "limited availability", "exclusive deal",
                "not many left", "popular item", "selling quickly",
                "limited quantities", "rare opportunity", "exclusive access",
                "members only", "vip access", "limited spots"
            ],
            "Forced Action": [
                "by signing up you agree", "cannot continue without",
                "required to proceed", "must accept", "mandatory subscription",
                "forced newsletter", "agree to receive", "cannot use without",
                "required field", "mandatory field", "you must",
                "required to continue", "required to access",
                "sign up to continue", "create account to proceed",
                "membership required", "subscription needed",
                "register to view", "login required", "account needed"
            ],
            "Misdirection": [
                "recommended option", "best choice", "most popular",
                "suggested plan", "everyone's choice", "trending choice",
                "preferred option", "premium selection", "expert's pick",
                "top choice", "best value", "most chosen",
                "staff pick", "featured option", "highlighted choice",
                "recommended for you", "personalized pick",
                "tailored selection", "custom choice", "smart choice"
            ],
            "Social Proof Manipulation": [
                "others are viewing", "recently purchased",
                "in cart now", "popular choice", "trending now",
                "bestseller", "top rated", "customer favorite",
                "'%' of users bought", "people are watching",
                "customers choose", "top seller", "most popular",
                "highly rated", "trending item", "frequently bought",
                "other customers", "popular in your area",
                "in high demand", "customers love"
            ],
            "Hidden Costs": [
                "processing fee", "service charge", "handling fee",
                "additional charges", "extra costs", "subscription required",
                "premium feature", "upgrade needed", "convenience fee",
                "shipping and handling", "taxes and fees",
                "additional services", "setup fee", "activation charge",
                "minimum purchase", "subscription fee", "recurring billing",
                "auto-renewal", "hidden fees", "terms apply"
            ],
            "Pressure Tactics": [
                "don't miss out", "once in a lifetime",
                "exclusive deal", "limited time offer", "special access",
                "insider price", "member exclusive", "restricted offer",
                "private sale", "exclusive pricing", "special invitation",
                "selected customers", "premium access", "exclusive group",
                "special selection", "handpicked offer"
            ],
            "Fake Urgency": [
                "only available today", "flash sale",
                "24-hour deal", "daily special", "today's offer",
                "one-time offer", "temporary price", "special promotion",
                "limited promotion", "flash deal", "instant access",
                "temporary access", "one-day only", "exclusive timing"
            ]
        }
        
        # Check for dark patterns in visible content
        for category, keywords in patterns.items():
            category_patterns = []
            for keyword in keywords:
                # Use regex for more flexible pattern matching
                pattern = re.compile(r'\b' + re.escape(keyword) + r'\b', re.IGNORECASE)
                matches = pattern.finditer(content)
                for match in matches:
                    # Get some context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].replace('\n', ' ').strip()
                    category_patterns.append(f"Found '{keyword}' in context: '...{context}...'")
            
            if category_patterns:
                dark_patterns.append(f"\n{category}:")
                dark_patterns.extend([f"  - {pattern}" for pattern in category_patterns])
        
        # Check for hidden elements
        hidden_elements = soup.find_all(['div', 'p', 'span', 'button', 'a'], 
                                      style=lambda value: value and any(
                                          pattern in value.lower() 
                                          for pattern in [
                                              'display:none', 
                                              'display: none',
                                              'visibility:hidden',
                                              'visibility: hidden',
                                              'opacity:0',
                                              'opacity: 0'
                                          ]
                                      ))
        
        # Check for elements with very small dimensions
        tiny_elements = soup.find_all(['div', 'p', 'span', 'button', 'a'],
                                    style=lambda value: value and any(
                                        pattern in value.lower()
                                        for pattern in [
                                            'width:1px',
                                            'height:1px',
                                            'font-size:1px',
                                            'font-size: 1px'
                                        ]
                                    ))
        
        # Add hidden elements to dark patterns list
        if hidden_elements or tiny_elements:
            dark_patterns.append("\nHidden Elements:")
            if hidden_elements:
                dark_patterns.append(f"  - Found {len(hidden_elements)} hidden elements that might affect user decisions")
            if tiny_elements:
                dark_patterns.append(f"  - Found {len(tiny_elements)} suspiciously small elements")
            
        # Check for exit intent popups (common dark pattern implementation)
        exit_intent_patterns = [
            'exit', 'leave', 'stay', 'wait', 'before you go',
            'don\'t leave', 'leaving so soon', 'closing tab'
        ]
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and any(pattern in script.string.lower() for pattern in exit_intent_patterns):
                dark_patterns.append("\nExit Intent Manipulation:")
                dark_patterns.append("  - Detected exit intent popup implementation")
                break
        
        # Check for countdown timers
        countdown_elements = soup.find_all(
            lambda tag: tag.name in ['div', 'span', 'p'] and
            any(word in tag.get_text().lower() for word in ['countdown', 'timer', 'expires in'])
        )
        if countdown_elements:
            dark_patterns.append("\nUrgency Countdown:")
            dark_patterns.append(f"  - Found {len(countdown_elements)} countdown timer(s)")
        
        # If no dark patterns were found
        if not dark_patterns:
            dark_patterns.append("No dark patterns detected")
            
        return dark_patterns
        
    except requests.exceptions.Timeout:
        return ["Error: Request timed out while analyzing the website"]
    except requests.exceptions.RequestException as e:
        return [f"Error: Could not access the website: {str(e)}"]
    except Exception as e:
        return [f"Error: An unexpected error occurred while analyzing dark patterns: {str(e)}"]
    

def check_dark_patterns_dynamic(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # Run in headless mode
    driver = webdriver.Chrome(options=chrome_options)
    
    try:
        driver.get(url)
        # Wait for dynamic content to load
        driver.implicitly_wait(5)
        # Get the page source after JavaScript execution
        page_source = driver.page_source
        # Use the existing function with the dynamic content
        return check_dark_patterns(page_source)
    finally:
        driver.quit()

def test_website_patterns(url):
    print(f"\nAnalyzing {url}...")
    try:
        patterns = check_dark_patterns(url)
        print("\nDetected Dark Patterns:")
        for pattern in patterns:
            print(pattern)
    except Exception as e:
        print(f"Error analyzing {url}: {str(e)}")



def calculate_malicious_score(vulnerabilities: List[str], 
                            security_issues: List[str], 
                            dark_patterns: List[str],
                            xss_vulnerabilities: List[str],
                            open_ports: List[str],
                            ssl_vulnerabilities: List[str]) -> int:
    score = 100
    
    # Weight different issues
    score -= len(vulnerabilities) * 10      # SQL injection: severe
    score -= len(xss_vulnerabilities) * 8   # XSS: very serious
    score -= len(security_issues) * 5       # Security headers: moderate
    score -= len(dark_patterns) * 3         # Dark patterns: minor
    score -= len(open_ports) * 4           # Open ports: moderate
    score -= len(ssl_vulnerabilities) * 6   # SSL issues: serious
    
    return max(0, score)

def create_scorecard(score: int) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': "Safety Score"},
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={
            'axis': {'range': [0, 100]},
            'steps': [
                {'range': [0, 30], 'color': "red"},
                {'range': [30, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "green"}
            ],
            'bar': {'color': "darkblue"}
        }
    ))
    
    fig.update_layout(height=300)
    return fig

def generate_huggingface_summary(llm_client: InferenceClient, 
                               url: str, 
                               score: int, 
                               vulnerabilities: List[str], 
                               security_issues: List[str], 
                               dark_patterns: List[str]) -> str:
    try:
        if score >= 80:
            summary_prompt = (
                f"The website {url} has been analyzed and found to be safe with a score of {score}%. "
                "Please provide a brief one-sentence confirmation of its safety."
            )
        else:
            summary_prompt = (
                f"URL: {url}\n\n"
                f"SQL Injection Vulnerabilities: {', '.join(vulnerabilities) if vulnerabilities else 'None detected'}\n"
                f"HTTP Security Issues: {', '.join(security_issues) if security_issues else 'None detected'}\n"
                f"Dark Patterns: {', '.join(dark_patterns) if dark_patterns else 'None detected'}\n"
                f"Safety Score: {score}\n\n"
                "Provide a summary of the detected issues and recommendations for improving the website's security and usability."
            )
        
        response = call_llm(llm_client, summary_prompt)
        return response
    except Exception as e:
        return f"Error generating summary: {str(e)}"

def main():
    st.set_page_config(
        page_title="Dark Pattern Detector",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.markdown("""
    <style>
        .main {
            background-color: #1E1E1E;
            color: white;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
        }
    </style>
    """, unsafe_allow_html=True)

    st.title("🔍 Dark Pattern & Security Analyzer")
    
    url = st.text_input("Enter Website URL:", "https://example.com")
    
    if st.button("Analyze Website"):
        if not url:
            st.error("Please enter a valid URL")
            return
            
        with st.spinner("Analyzing website..."):
            # Perform all security checks
            vulnerabilities = check_sql_injection_vulnerability(url)
            security_issues = analyze_http_security(url)
            dark_patterns = check_dark_patterns(url)
            xss_vulnerabilities = check_xss_vulnerability(url)
            open_ports = check_open_ports(url)
            ssl_vulnerabilities = check_ssl_vulnerabilities(url)
            
            # Calculate score
            score = calculate_malicious_score(
                vulnerabilities, security_issues, dark_patterns,
                xss_vulnerabilities, open_ports, ssl_vulnerabilities
            )
            
            # Display results in columns
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.subheader("Detailed Report")
                
                # SQL Injection Vulnerabilities
                st.markdown("### SQL Injection Vulnerabilities")
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        st.warning(vuln)
                else:
                    st.success("No SQL injection vulnerabilities detected")
                
                # XSS Vulnerabilities
                st.markdown("### XSS Vulnerabilities")
                if xss_vulnerabilities:
                    for vuln in xss_vulnerabilities:
                        st.warning(vuln)
                else:
                    st.success("No XSS vulnerabilities detected")
                
                # Open Ports
                st.markdown("### Open Ports")
                if open_ports:
                    for port in open_ports:
                        st.warning(port)
                else:
                    st.success("No concerning open ports detected")
                
                # SSL Vulnerabilities
                st.markdown("### SSL Vulnerabilities")
                if ssl_vulnerabilities:
                    for vuln in ssl_vulnerabilities:
                        st.warning(vuln)
                else:
                    st.success("No SSL vulnerabilities detected")
                    
                # Security Issues
                st.markdown("### HTTP Security Issues")
                if security_issues:
                    for issue in security_issues:
                        st.warning(issue)
                else:
                    st.success("No security issues detected")
                    
                # Dark Patterns
                st.markdown("### Dark Patterns Detected")
                if dark_patterns:
                    for pattern in dark_patterns:
                        st.warning(pattern)
                else:
                    st.success("No dark patterns detected")
            
            with col2:
                st.subheader("Safety Score")
                st.plotly_chart(create_scorecard(score))
                
                if score >= 70:
                    st.success(f"Overall Rating: Safe ({score}%)")
                elif score >= 30:
                    st.warning(f"Overall Rating: Moderate Risk ({score}%)")
                else:
                    st.error(f"Overall Rating: High Risk ({score}%)")
            
            # Generate and display the summary
            llm_summary = generate_huggingface_summary(
                llm_client, url, score,
                vulnerabilities, security_issues, dark_patterns
            )
            st.markdown("### AI-Generated Summary")
            st.text_area("Summary", llm_summary, height=200)

if __name__ == "__main__":
    main()