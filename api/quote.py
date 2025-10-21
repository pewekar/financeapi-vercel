import json
import yfinance as yf

def handler(request):
    symbols = request.query.get("symbols", "AAPL,MSFT,GOOG,ORCL,TSLA")
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
