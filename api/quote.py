from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import json
import yfinance as yf
from datetime import datetime, timedelta
import hashlib
import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory storage (persists across warm container invocations)
_cache = {}
_rate_limits = {}

# Configuration
CACHE_DURATION = 300  # 5 minutes in seconds
MAX_SYMBOLS = 10
MAX_SYMBOL_LENGTH = 10
RATE_LIMIT = 50  # Max requests per IP per hour
RATE_LIMIT_WINDOW = 3600  # 1 hour in seconds

# Valid stock symbol pattern
SYMBOL_PATTERN = re.compile(r'^[A-Z0-9.\-]{1,10}$')


def get_client_ip(handler):
    """Extract client IP from request headers"""
    # Try Vercel's forwarding headers first
    forwarded = handler.headers.get('x-forwarded-for')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    real_ip = handler.headers.get('x-real-ip')
    if real_ip:
        return real_ip
    
    return handler.client_address[0] if handler.client_address else 'unknown'


def check_rate_limit(ip):
    """Check if IP has exceeded rate limit"""
    now = datetime.now()
    
    # Clean up old entries
    expired = [k for k, v in _rate_limits.items() 
               if now - v['reset_time'] > timedelta(seconds=RATE_LIMIT_WINDOW)]
    for k in expired:
        del _rate_limits[k]
    
    if ip not in _rate_limits:
        _rate_limits[ip] = {'count': 1, 'reset_time': now}
        return True, RATE_LIMIT - 1
    
    data = _rate_limits[ip]
    
    # Reset if window expired
    if now - data['reset_time'] > timedelta(seconds=RATE_LIMIT_WINDOW):
        data['count'] = 1
        data['reset_time'] = now
        return True, RATE_LIMIT - 1
    
    # Check limit
    if data['count'] >= RATE_LIMIT:
        return False, 0
    
    data['count'] += 1
    return True, RATE_LIMIT - data['count']


def validate_symbols(symbols_str):
    """Validate and sanitize symbol input"""
    if not symbols_str or not isinstance(symbols_str, str):
        return None, "Invalid symbols parameter"
    
    # Split and clean
    symbols = [s.strip().upper() for s in symbols_str.split(',') if s.strip()]
    
    if len(symbols) == 0:
        return None, "No symbols provided"
    
    if len(symbols) > MAX_SYMBOLS:
        return None, f"Too many symbols. Maximum is {MAX_SYMBOLS}"
    
    # Validate each symbol
    for symbol in symbols:
        if len(symbol) > MAX_SYMBOL_LENGTH:
            return None, f"Symbol too long: {symbol}"
        if not SYMBOL_PATTERN.match(symbol):
            return None, f"Invalid symbol format: {symbol}"
    
    return symbols, None


def get_cache_key(symbols):
    """Generate cache key from symbols list"""
    key_str = ','.join(sorted(symbols))
    return hashlib.md5(key_str.encode()).hexdigest()


def get_from_cache(cache_key):
    """Retrieve data from cache if still valid"""
    if cache_key in _cache:
        data, timestamp = _cache[cache_key]
        if datetime.now() - timestamp < timedelta(seconds=CACHE_DURATION):
            return data
        del _cache[cache_key]
    return None


def set_cache(cache_key, data):
    """Store data in cache with timestamp"""
    # Limit cache size
    if len(_cache) > 1000:
        sorted_cache = sorted(_cache.items(), key=lambda x: x[1][1])
        for k, _ in sorted_cache[:200]:
            del _cache[k]
    
    _cache[cache_key] = (data, datetime.now())


def fetch_stock_data(symbols):
    """Fetch stock data from Yahoo Finance"""
    try:
        symbols_str = ' '.join(symbols)
        tickers = yf.Tickers(symbols_str)
        result = {}
        
        for symbol in symbols:
            try:
                ticker = tickers.tickers.get(symbol)
                if not ticker:
                    result[symbol] = {
                        "status": "error",
                        "error": "Symbol not found"
                    }
                    continue
                
                info = ticker.get_info()
                result[symbol] = {
                    "price": info.get("currentPrice"),
                    "peRatio": info.get("trailingPE"),
                    "dividendYield": info.get("dividendYield"),
                    "marketCap": info.get("marketCap"),
                    "status": "success"
                }
            except Exception as e:
                logger.warning(f"Failed to fetch {symbol}: {str(e)}")
                result[symbol] = {
                    "status": "error",
                    "error": "Data unavailable"
                }
        
        return result, None
    
    except Exception as e:
        logger.error(f"Batch fetch failed: {str(e)}")
        return None, "Service temporarily unavailable"


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        start_time = datetime.now()
        
        # Get client IP
        client_ip = get_client_ip(self)
        
        # Check rate limit
        allowed, remaining = check_rate_limit(client_ip)
        if not allowed:
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            self.send_response(429)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Retry-After', '3600')
            self.send_header('X-RateLimit-Limit', str(RATE_LIMIT))
            self.send_header('X-RateLimit-Remaining', '0')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": "Rate limit exceeded. Maximum 50 requests per hour.",
                "retryAfter": 3600
            }).encode())
            return
        
        # Parse query parameters
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        symbols_param = query_params.get('symbols', ['AAPL,MSFT,GOOG'])[0]
        
        # Validate symbols
        symbols, error = validate_symbols(symbols_param)
        if error:
            logger.warning(f"Invalid input from {client_ip}: {error}")
            self.send_response(400)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"error": error}).encode())
            return
        
        # Check cache
        cache_key = get_cache_key(symbols)
        cached_data = get_from_cache(cache_key)
        
        if cached_data:
            exec_time = (datetime.now() - start_time).total_seconds()
            logger.info(f"Cache hit for {','.join(symbols)} ({exec_time:.2f}s)")
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Cache-Control', f'public, max-age={CACHE_DURATION}')
            self.send_header('X-Cache', 'HIT')
            self.send_header('X-RateLimit-Limit', str(RATE_LIMIT))
            self.send_header('X-RateLimit-Remaining', str(remaining))
            self.send_header('X-Execution-Time', f'{exec_time:.3f}s')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.end_headers()
            
            response = {
                "data": cached_data,
                "cached": True,
                "timestamp": datetime.now().isoformat()
            }
            self.wfile.write(json.dumps(response, indent=2).encode())
            return
        
        # Fetch fresh data
        logger.info(f"Fetching data for {','.join(symbols)}")
        result, error = fetch_stock_data(symbols)
        
        if error:
            exec_time = (datetime.now() - start_time).total_seconds()
            logger.error(f"Fetch failed: {error} ({exec_time:.2f}s)")
            
            self.send_response(504)
            self.send_header('Content-Type', 'application/json')
            self.send_header('X-RateLimit-Limit', str(RATE_LIMIT))
            self.send_header('X-RateLimit-Remaining', str(remaining))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            
            self.wfile.write(json.dumps({
                "error": error,
                "symbols": symbols
            }).encode())
            return
        
        # Cache the result
        set_cache(cache_key, result)
        
        exec_time = (datetime.now() - start_time).total_seconds()
        logger.info(f"Successfully fetched {','.join(symbols)} ({exec_time:.2f}s)")
        
        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', f'public, max-age={CACHE_DURATION}')
        self.send_header('X-Cache', 'MISS')
        self.send_header('X-RateLimit-Limit', str(RATE_LIMIT))
        self.send_header('X-RateLimit-Remaining', str(remaining))
        self.send_header('X-Execution-Time', f'{exec_time:.3f}s')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.end_headers()
        
        response = {
            "data": result,
            "cached": False,
            "timestamp": datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response, indent=2).encode())
