import json
import yfinance as yf
from urllib.parse import parse_qs

def handler(request):
    # Parse query string from the request
    query_string = request.get('query', '')
    params = parse_qs(query_string) if query_string else {}
    
    # Get symbols from query params, default to common stocks
    symbols = params.get('symbols', ['AAPL,MSFT,GOOG,ORCL,TSLA'])[0]
    
    try:
        tickers = yf.Tickers(symbols.replace(",", " "))
        
        result = {}
        for symbol, ticker in tickers.tickers.items():
            info = ticker.get_info()
            result[symbol] = {
                "price": info.get("currentPrice"),
                "peRatio": info.get("trailingPE"),
                "dividendYield": info.get("dividendYield"),
                "marketCap": info.get("marketCap")
            }
        
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(result)
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(e)})
        }
