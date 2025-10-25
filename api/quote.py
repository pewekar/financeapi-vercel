import json
import yfinance as yf
from urllib.parse import parse_qs
from datetime import datetime, timedelta
import hashlib

# Simple in-memory cache (will persist across invocations in warm containers)
_cache = {}
CACHE_DURATION = 300  # 5 minutes in seconds

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
    _cache[cache_key] = (data, datetime.now())

def fetch_stock_data(symbols_str, timeout=8):
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
        # Windows or alarm not available, continue without timeout
        pass
    
    try:
        tickers = yf.Tickers(symbols_str.replace(",", " "))
        result = {}
        
        for symbol, ticker in tickers.tickers.items():
            try:
                info = ticker.get_info()
                result[symbol] = {
                    "price": info.get("currentPrice"),
                    "peRatio": info.get("trailingPE"),
                    "dividendYield": info.get("dividendYield"),
                    "marketCap": info.get("marketCap"),
                    "status": "success"
                }
            except Exception as e:
                # Individual stock fetch failed
                result[symbol] = {
                    "status": "error",
                    "error": f"Failed to fetch data: {str(e)}"
                }
        
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
        return None, "Request timed out. Try fewer symbols or try again later."
    
    except Exception as e:
        try:
            signal.alarm(0)
        except (AttributeError, ValueError):
            pass
        return None, f"API error: {str(e)}"

def handler(request):
    # Parse query string from the request
    query_string = request.get('query', '')
    params = parse_qs(query_string) if query_string else {}
    
    # Get symbols from query params, default to common stocks
    symbols = params.get('symbols', ['AAPL,MSFT,GOOG'])[0]
    
    # Limit number of symbols to prevent timeouts
    symbol_list = [s.strip().upper() for s in symbols.split(',')]
    if len(symbol_list) > 10:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "error": "Too many symbols requested. Maximum is 10 symbols per request."
            })
        }
    
    symbols_normalized = ','.join(symbol_list)
    cache_key = get_cache_key(symbols_normalized)
    
    # Check cache first
    cached_data = get_from_cache(cache_key)
    if cached_data:
        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json",
                "X-Cache": "HIT"
            },
            "body": json.dumps({
                "data": cached_data,
                "cached": True,
                "timestamp": datetime.now().isoformat()
            })
        }
    
    # Fetch fresh data
    result, error = fetch_stock_data(symbols_normalized, timeout=8)
    
    if error:
        return {
            "statusCode": 504,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({
                "error": error,
                "symbols": symbol_list
            })
        }
    
    # Cache the successful result
    set_cache(cache_key, result)
    
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-Cache": "MISS"
        },
        "body": json.dumps({
            "data": result,
            "cached": False,
            "timestamp": datetime.now().isoformat()
        })
    }
