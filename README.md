# Stock Quote API

A secure, robust, and performant serverless API for fetching real-time stock quotes using Yahoo Finance data.

## Features

### Security
- **Input Validation**: Strict validation of stock symbols using regex patterns
- **Rate Limiting**: IP-based rate limiting (50 requests/hour per IP)
- **Sanitization**: All inputs are sanitized to prevent injection attacks
- **Security Headers**: OWASP-recommended HTTP security headers
- **Error Masking**: Generic error messages prevent information leakage

### Performance
- **Multi-level Caching**: 
  - In-memory cache with 5-minute TTL
  - LRU cache for individual ticker lookups
  - HTTP Cache-Control headers
- **Batch Processing**: Fetches multiple symbols efficiently
- **Timeout Protection**: 8-second timeout prevents hanging requests
- **Cache Size Management**: Automatic cleanup when cache exceeds 1000 entries

### Robustness
- **Graceful Degradation**: Per-symbol error handling
- **Comprehensive Logging**: Structured logging for debugging
- **Fallback Mechanisms**: Automatic fallback to individual fetches
- **Memory Management**: Prevents unbounded cache growth
- **Request Metrics**: Execution time tracking

##Crypto Support Added!
✅ What's New
Dual Asset Support:

📊 Stocks: Yahoo Finance (Apple, Tesla, Microsoft, etc.)
🪙 Crypto: CoinGecko API (Bitcoin, Ethereum, Solana, etc.)
🔀 Mixed: Query stocks and crypto in the same request!

30+ Supported Cryptocurrencies:

BTC, ETH, SOL, BNB, XRP, ADA, DOGE, MATIC, LINK, DOT
AVAX, UNI, ATOM, LTC, BCH, XLM, ALGO, FIL, ICP, APT
ARB, OP, NEAR, STX, TON, TRX, USDT, USDC, SHIB, and more!

Crypto-Specific Data:

Current price in USD
Market cap
24-hour price change percentage
## API Endpoint
GET https://financeapi-vercel-git-main-pewekar.vercel.app/api/quote?symbols=AAPL,TSLA,BTC,ETH,SOL/api/quote?symbols=AAPL,MSFT,GOOG

### Query Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| symbols | string | No | AAPL,MSFT,GOOG | Comma-separated stock symbols (max 10) |

### Response Format

```json
{
  "data": {
    "AAPL": {
      "price": 178.25,
      "peRatio": 28.5,
      "dividendYield": 0.0052,
      "marketCap": 2800000000000,
      "status": "success"
    },
    "MSFT": {
      "price": 378.91,
      "peRatio": 35.2,
      "dividendYield": 0.0075,
      "marketCap": 2810000000000,
      "status": "success"
    }
  },
  "cached": false,
  "timestamp": "2025-10-25T12:00:00.000000"
}
```

### Response Headers

| Header | Description |
|--------|-------------|
| X-Cache | HIT or MISS indicating cache status |
| X-RateLimit-Limit | Maximum requests allowed per hour |
| X-RateLimit-Remaining | Remaining requests in current window |
| X-Execution-Time | Request execution time in seconds |
| Cache-Control | HTTP caching directive |

### Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 400 | Bad Request (invalid symbols) |
| 429 | Too Many Requests (rate limit exceeded) |
| 504 | Gateway Timeout (API timeout) |

## Validation Rules

- **Symbol Format**: Alphanumeric, dots, and hyphens only (e.g., `BRK.B`, `VOO`)
- **Symbol Length**: Maximum 10 characters per symbol
- **Symbol Count**: Maximum 10 symbols per request
- **Rate Limit**: 50 requests per hour per IP address

## Examples

### Basic Request
```bash
curl "https://your-app.vercel.app/api/quote?symbols=AAPL,MSFT"
```

### Check Cache Status
```bash
curl -i "https://your-app.vercel.app/api/quote?symbols=AAPL"
# First request: X-Cache: MISS
# Second request (within 5 min): X-Cache: HIT
```

### Check Rate Limit
```bash
curl -i "https://your-app.vercel.app/api/quote?symbols=TSLA"
# Headers include:
# X-RateLimit-Limit: 50
# X-RateLimit-Remaining: 49
```

### Error Handling
```bash
# Invalid symbol
curl "https://your-app.vercel.app/api/quote?symbols=INVALID@@@"
# Response: {"error": "Invalid symbol format: INVALID@@@"}

# Too many symbols
curl "https://your-app.vercel.app/api/quote?symbols=A,B,C,D,E,F,G,H,I,J,K"
# Response: {"error": "Too many symbols. Maximum is 10 per request"}
```

## Deployment

### Prerequisites
- Vercel account
- Vercel CLI (optional)

### Deploy with Vercel CLI
```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel deploy --prod
```

### Deploy via GitHub
1. Connect your repository to Vercel
2. Push changes to main branch
3. Automatic deployment triggered

### Environment Variables
No environment variables required. The API uses public Yahoo Finance data.

## Configuration

Edit these constants in `api/quote.py` to customize behavior:

```python
CACHE_DURATION = 300  # Cache TTL in seconds (default: 5 minutes)
MAX_SYMBOLS = 10  # Max symbols per request
MAX_SYMBOL_LENGTH = 10  # Max characters per symbol
REQUEST_LIMIT = 50  # Max requests per IP per hour
RATE_LIMIT_WINDOW = 3600  # Rate limit window in seconds (1 hour)
```

## Monitoring

The API logs important events:

- Cache hits/misses
- Execution times
- Failed requests
- Rate limit violations
- Invalid inputs

Access logs via Vercel dashboard or CLI:
```bash
vercel logs
```

## Performance Considerations

- **First Request**: 2-5 seconds (fetches from Yahoo Finance)
- **Cached Request**: 50-100ms
- **Warm Container**: Faster responses due to in-memory cache
- **Cold Start**: Initial request may take longer

## Limitations

- **Data Source**: Uses Yahoo Finance (free, no API key required)
- **Rate Limits**: 50 requests/hour per IP (adjustable)
- **Function Timeout**: 10 seconds (Vercel free tier)
- **Cache Scope**: Per-container (not distributed)
- **Historical Data**: Not supported (real-time only)

## Security Best Practices

✅ Implemented:
- Input validation and sanitization
- Rate limiting
- Security headers
- Error masking
- Timeout protection
- Memory limits

⚠️ Recommendations:
- Use Vercel KV for distributed caching
- Implement API key authentication for production
- Add CORS configuration if needed
- Monitor logs for suspicious activity
- Set up alerts for rate limit violations

## Troubleshooting

### Timeout Errors
- Reduce number of symbols requested
- Check Yahoo Finance service status
- Increase function timeout in `vercel.json`

### Rate Limit Errors
- Wait 1 hour for limit reset
- Adjust `REQUEST_LIMIT` for your needs
- Use caching to reduce API calls

### Invalid Symbol Errors
- Verify symbol format (uppercase, no special chars except dots/hyphens)
- Check symbol exists on Yahoo Finance
- Maximum 10 characters per symbol

## License

MIT

## Support

For issues and questions:
- Check Vercel logs: `vercel logs`
- Review error responses
- Check Yahoo Finance status: https://finance.yahoo.com
