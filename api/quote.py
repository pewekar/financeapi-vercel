import json
import yfinance as yf
from urllib.parse import parse_qs
from datetime import datetime, timedelta
import hashlib
import logging
import re
from functools import lru_cache

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Simple in-memory cache (will persist across invocations in warm containers)
_cache = {}
_request_counts = {}  # For rate limiting by IP
CACHE_DURATION = 300  # 5 minutes in seconds
MAX_SYMBOLS = 10
MAX_SYMBOL_LENGTH = 10
REQUEST_LIMIT = 50  # Max requests per IP per hour
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

# Valid stock symbol pattern (letters, numbers, dots, hyphens)
SYMBOL_PATTERN = re.compile(r'^[A-Z0-9.\-]{1,10}$')

def get_client_ip(environ):
    """Extract client IP from WSGI environ"""
    return (
        environ.get('HTTP_X_REAL_IP') or 
        environ.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or
        environ.get('REMOTE_ADDR', 'unknown')
    )

def check_rate_limit(ip):
    """Check if IP has exceeded rate limit"""
    now = datetime.now()
    
    # Clean up old entries
    expired_ips = [
        k for k, v in _request_counts.items() 
        if now - v['reset_time'] > timedelta(seconds=RATE_LIMIT_WINDOW)
    ]
    for ip_key in expired_ips:
        del _request_counts[ip_key]
    
    if ip not in _request_counts:
        _request_counts[ip] = {
            'count': 1,
            'reset_time': now
        }
        return True, REQUEST_LIMIT - 1
    
    ip_data = _request_counts[ip]
    
    # Reset if window expired
    if now - ip_data['reset_time'] > timedelta(seconds=RATE_LIMIT_WINDOW):
        ip_data['count'] = 1
        ip_data['reset_time'] = now
        return True, REQUEST_LIMIT - 1
    
    # Check limit
    if ip_data['count'] >= REQUEST_LIMIT:
        return False, 0
    
    ip_data['count'] += 1
    return True, REQUEST_LIMIT - ip_data['count']

def sanitize_symbols(symbols_str):
    """Validate and sanitize symbol input"""
    if not symbols_str or not isinstance(symbols_str, str):
        return None, "Invalid symbols parameter"
    
    # Remove whitespace and convert to uppercase
    symbol_list = [s.strip().upper() for s in symbols_str.split(',') if s.strip()]
    
    # Check number of symbols
    if len(symbol_list) == 0:
        return None, "No symbols provided"
    
    if len(symbol_list) > MAX_SYMBOLS:
        return None, f"Too many symbols. Maximum is {MAX_SYMBOLS} per request"
    
    # Validate each symbol
    validated = []
    for symbol in symbol_list:
        if len(symbol) > MAX_SYMBOL_LENGTH:
            return None, f"Symbol too long: {symbol}"
        
        if not SYMBOL_PATTERN.match(symbol):
            return None, f"Invalid symbol format: {symbol}"
        
        validated.append(symbol)
    
    return validated, None

def get_cache_key(symbols):
    """Generate a cache key from symbols"""
    return hashlib.md5(symbols.encode()).hexdigest()

def get_from_cache(cache_key):
    """Retrieve data from cache if still valid"""
    if cache_key in _cache:
        data, timestamp = _cache[cache_key]
        if datetime.now() - timestamp < timedelta(seconds=CACHE_DURATION):
            return data
        else:
            # Cache expired, remove it
            del _cache[cache_key]
    return None

def set_cache(cache_key, data):
    """Store data in cache with timestamp"""
    # Limit cache size to prevent memory issues
    if len(_cache) > 1000:
        # Remove oldest 20% of entries
        sorted_cache = sorted(_cache.items(), key=lambda x: x[1][1])
        for key, _ in sorted_cache[:200]:
            del _cache[key]
    
    _cache[cache_key] = (data, datetime.now())

@lru_cache(maxsize=100)
def get_ticker_info_cached(symbol):
    """Cached wrapper for individual ticker info"""
    try:
        ticker = yf.Ticker(symbol)
        info = ticker.get_info()
        return {
            "price": info.get("currentPrice"),
            "peRatio": info.get("trailingPE"),
            "dividendYield": info.get("dividendYield"),
            "marketCap": info.get("marketCap"),
            "status": "success"
        }
    except Exception as e:
        logger.warning(f"Failed to fetch {symbol}: {str(e)}")
        return {
            "status": "error",
            "error": "Data unavailable"
        }

def fetch_stock_data(symbol_list, timeout=8):
    """Fetch stock data with timeout and error handling"""
    import signal
    
    class TimeoutError(Exception):
        pass
    
    def timeout_handler(signum, frame):
        raise TimeoutError("Request timed out")
    
    # Set up timeout (only works on Unix-based systems)
    try:
        signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)
    except (AttributeError, ValueError):
        pass
    
    try:
        result = {}
        
        # Fetch symbols in batch for better performance
        try:
            symbols_str = ' '.join(symbol_list)
            tickers = yf.Tickers(symbols_str)
            
            for symbol in symbol_list:
                try:
                    ticker = tickers.tickers.get(symbol)
                    if ticker:
                        info = ticker.get_info()
                        result[symbol] = {
                            "price": info.get("currentPrice"),
                            "peRatio": info.get("trailingPE"),
                            "dividendYield": info.get("dividendYield"),
                            "marketCap": info.get("marketCap"),
                            "status": "success"
                        }
                    else:
                        result[symbol] = {
                            "status": "error",
                            "error": "Symbol not found"
                        }
                except Exception as e:
                    logger.warning(f"Failed to fetch {symbol}: {str(e)}")
                    result[symbol] = {
                        "status": "error",
                        "error": "Data unavailable"
                    }
        except Exception as e:
            logger.error(f"Batch fetch failed: {str(e)}")
            # Fallback to individual fetches
            for symbol in symbol_list:
                result[symbol] = get_ticker_info_cached(symbol)
        
        # Cancel the alarm
        try:
            signal.alarm(0)
        except (AttributeError, ValueError):
            pass
        
        return result, None
        
    except TimeoutError:
        try:
            signal.alarm(0)
        except (AttributeError, ValueError):
            pass
        logger.error("Request timed out")
        return None, "Request timed out. Try fewer symbols or try again later."
    
    except Exception as e:
        try:
            signal.alarm(0)
        except (AttributeError, ValueError):
            pass
        logger.error(f"Unexpected error: {str(e)}")
        return None, f"Service temporarily unavailable"

def handler(environ, start_response):
    """WSGI handler for Vercel"""
    start_time = datetime.now()
    
    # Get client IP for rate limiting
    client_ip = get_client_ip(environ)
    
    # Check rate limit
    allowed, remaining = check_rate_limit(client_ip)
    if not allowed:
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        headers = [
            ('Content-Type', 'application/json'),
            ('Retry-After', '3600'),
            ('X-RateLimit-Limit', str(REQUEST_LIMIT)),
            ('X-RateLimit-Remaining', '0')
        ]
        start_response('429 Too Many Requests', headers)
        return [json.dumps({
            "error": "Rate limit exceeded. Maximum 50 requests per hour.",
            "retryAfter": 3600
        }).encode()]
    
    # Parse query string
    query_string = environ.get('QUERY_STRING', '')
    params = parse_qs(query_string)
    
    # Get symbols from query params
    symbols_param = params.get('symbols', ['AAPL,MSFT,GOOG'])[0]
    
    # Validate and sanitize input
    symbol_list, error = sanitize_symbols(symbols_param)
    if error:
        logger.warning(f"Invalid input from {client_ip}: {error}")
        headers = [('Content-Type', 'application/json')]
        start_response('400 Bad Request', headers)
        return [json.dumps({"error": error}).encode()]
    
    symbols_normalized = ','.join(symbol_list)
    cache_key = get_cache_key(symbols_normalized)
    
    # Check cache first
    cached_data = get_from_cache(cache_key)
    if cached_data:
        execution_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Cache hit for {symbols_normalized} ({execution_time:.2f}s)")
        headers = [
            ('Content-Type', 'application/json'),
            ('Cache-Control', f'public, max-age={CACHE_DURATION}'),
            ('X-Cache', 'HIT'),
            ('X-RateLimit-Limit', str(REQUEST_LIMIT)),
            ('X-RateLimit-Remaining', str(remaining)),
            ('X-Execution-Time', f'{execution_time:.3f}s')
        ]
        start_response('200 OK', headers)
        return [json.dumps({
            "data": cached_data,
            "cached": True,
            "timestamp": datetime.now().isoformat()
        }).encode()]
    
    # Fetch fresh data
    logger.info(f"Fetching data for {symbols_normalized}")
    result, error = fetch_stock_data(symbol_list, timeout=8)
    
    if error:
        execution_time = (datetime.now() - start_time).total_seconds()
        logger.error(f"Fetch failed: {error} ({execution_time:.2f}s)")
        headers = [
            ('Content-Type', 'application/json'),
            ('X-RateLimit-Limit', str(REQUEST_LIMIT)),
            ('X-RateLimit-Remaining', str(remaining))
        ]
        start_response('504 Gateway Timeout', headers)
        return [json.dumps({
            "error": error,
            "symbols": symbol_list
        }).encode()]
    
    # Cache the successful result
    set_cache(cache_key, result)
    
    execution_time = (datetime.now() - start_time).total_seconds()
    logger.info(f"Successfully fetched {symbols_normalized} ({execution_time:.2f}s)")
    
    headers = [
        ('Content-Type', 'application/json'),
        ('Cache-Control', f'public, max-age={CACHE_DURATION}'),
        ('X-Cache', 'MISS'),
        ('X-RateLimit-Limit', str(REQUEST_LIMIT)),
        ('X-RateLimit-Remaining', str(remaining)),
        ('X-Execution-Time', f'{execution_time:.3f}s')
    ]
    start_response('200 OK', headers)
    return [json.dumps({
        "data": result,
        "cached": False,
        "timestamp": datetime.now().isoformat()
    }).encode()]
