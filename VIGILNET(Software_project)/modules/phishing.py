import requests
from urllib.parse import urlparse
import tldextract

def check_phishing_url(url):
    try:
        # Check domain age (simplified)
        domain = urlparse(url).netloc
        ext = tldextract.extract(domain)
        domain_name = f"{ext.domain}.{ext.suffix}"
        
        # Check for suspicious patterns
        suspicious = False
        if '-' in domain_name or len(domain_name.split('.')[0]) > 15:
            suspicious = True
            
        # Check if URL is in phishing databases (simulated)
        phishing_dbs = ['phish1.com', 'phish2.org']
        in_db = False  # In real implementation, would check actual APIs
        
        return {
            'domain': domain_name,
            'suspicious': suspicious,
            'in_phishing_db': in_db,
            'message': 'Caution advised' if suspicious else 'Seems legitimate'
        }
    except:
        return {'error': 'Invalid URL'}