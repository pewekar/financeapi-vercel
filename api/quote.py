from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import json
import yfinance as yf

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Parse the URL and query parameters
        parsed_path = urlparse(self.path)
        query_params = parse_qs(parsed_path.query)
        
        # Get symbols parameter (default to AAPL if not provided)
        symbols = query_params.get('symbols', ['AAPL'])[0]
        
        try:
            # Fetch stock data
            tickers = yf.Tickers(symbols.replace(",", " "))
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
                    result[symbol] = {
                        "status": "error",
                        "error": str(e)
                    }
            
            # Send successful response
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result, indent=2).encode())
            return
            
        except Exception as e:
            # Send error response
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": str(e),
                "message": "Failed to fetch stock data"
            }).encode())
            return
