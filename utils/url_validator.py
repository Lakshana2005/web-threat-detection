# utils/url_validator.py

import re
from urllib.parse import urlparse

def is_valid_url(url):
    """
    Validates if the given string is a proper URL
    Returns: (bool, str) - (is_valid, error_message)
    """
    
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty"
    
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Check minimum length
    if len(url) < 4:
        return False, "URL is too short"
    
    # Check for basic URL patterns
    # Must have at least a domain with TLD (example.com)
    url_pattern = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'|'  # OR
        r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}'  # domain.com
    )
    
    if not url_pattern.match(url):
        # Try adding http:// temporarily for validation
        temp_url = "http://" + url if not url.startswith(('http://', 'https://')) else url
        parsed = urlparse(temp_url)
        
        # Check if it has a valid domain structure
        if not parsed.netloc or '.' not in parsed.netloc:
            return False, "Invalid URL format - missing domain"
        
        # Check for invalid characters
        invalid_chars = [' ', '"', "'", '<', '>', '\\', '`']
        if any(char in url for char in invalid_chars):
            return False, "URL contains invalid characters"
    
    return True, "Valid URL"

def normalize_and_validate(url):
    """
    Normalize URL and validate it
    Returns: (normalized_url, is_valid, error_message)
    """
    if not url:
        return url, False, "URL is required"
    
    url = url.strip()
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Validate
    is_valid, message = is_valid_url(url)
    
    if not is_valid:
        return url, False, message
    
    return url, True, "Valid URL"
