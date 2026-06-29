import re

# Flexible provider context: provider_api_key = value
_CTX = r'(?i)(?:{alias})[_\s]*(?:api[_\s]*key|api[_\s]*token|access[_\s]*token|auth[_\s]*token|secret[_\s]*key)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{{8,}})[\'"]?'


def _ctx(alias, label):
    return (re.compile(_CTX.format(alias=alias)), label)


def _env(names, label):
    joined = '|'.join(re.escape(n) for n in names)
    return (re.compile(rf'(?i)^({joined})\s*=\s*([^\s#]+)', re.MULTILINE), label)


# (regex alias, human label) — stock, news, sports, weather, crypto, maps, social
_NAMED_PROVIDERS = [
    # Stock / finance / trading
    ('alpha[_\\s]*vantage|alphavantage', 'Alpha Vantage API Key'),
    ('polygon(?:[_\\s]*io)?', 'Polygon.io API Key'),
    ('finnhub', 'Finnhub API Key'),
    ('iex(?:[_\\s]*cloud)?', 'IEX Cloud API Key'),
    ('twelve[_\\s]*data', 'Twelve Data API Key'),
    ('marketstack', 'Marketstack API Key'),
    ('quandl|nasdaq[_\\s]*data[_\\s]*link', 'Nasdaq Data Link API Key'),
    ('tiingo', 'Tiingo API Key'),
    ('eod(?:hd|[_\\s]*historical)?', 'EOD Historical Data API Key'),
    ('financial[_\\s]*modeling[_\\s]*prep|fmp', 'Financial Modeling Prep API Key'),
    ('intrinio', 'Intrinio API Key'),
    ('barchart', 'Barchart API Key'),
    ('tradier', 'Tradier API Key'),
    ('benzinga', 'Benzinga API Key'),
    ('alpaca(?:[_\\s]*markets)?', 'Alpaca API Key'),
    ('xignite', 'Xignite API Key'),
    ('trading[_\\s]*economics', 'Trading Economics API Key'),
    ('fred(?:[_\\s]*api)?', 'FRED API Key'),
    ('bls(?:[_\\s]*api)?', 'BLS API Key'),
    ('bea(?:[_\\s]*api)?', 'BEA API Key'),
    ('sec[_\\s]*edgar|edgar[_\\s]*api', 'SEC EDGAR API Key'),
    ('cboe', 'CBOE API Key'),
    ('oanda', 'OANDA API Key'),
    ('fxcm', 'FXCM API Key'),
    ('interactive[_\\s]*brokers|ibkr', 'Interactive Brokers API Key'),
    ('td[_\\s]*ameritrade|schwab', 'Schwab API Key'),
    ('plaid', 'Plaid API Key'),
    ('stripe', 'Stripe API Key'),
    ('square|block[_\\s]*api', 'Square API Key'),
    ('yahoo[_\\s]*finance', 'Yahoo Finance API Key'),
    ('world[_\\s]*trading[_\\s]*data', 'World Trading Data API Key'),
    ('market[_\\s]*data', 'Market Data API Key'),
    ('stock[_\\s]*data', 'Stock Data API Key'),
    ('dxfeed', 'dxFeed API Key'),
    ('factset', 'FactSet API Key'),
    ('refinitiv|eikon', 'Refinitiv API Key'),
    ('bloomberg', 'Bloomberg API Key'),
    ('morningstar', 'Morningstar API Key'),
    ('simfin', 'SimFin API Key'),
    ('sharadar|nasdaq[_\\s]*datalink', 'Sharadar API Key'),
    ('databento', 'Databento API Key'),
    ('finage', 'Finage API Key'),
    ('finn[_\\s]*world', 'Finnworld API Key'),
    ('wallstreetzen', 'WallStreetZen API Key'),
    ('zacks', 'Zacks API Key'),
    ('seeking[_\\s]*alpha', 'Seeking Alpha API Key'),
    ('tradingview', 'TradingView API Key'),
    ('robinhood', 'Robinhood API Key'),
    ('etrade|e[_\\s]*trade', 'E*TRADE API Key'),
    ('fidelity', 'Fidelity API Key'),
    ('questrade', 'Questrade API Key'),
    ('ig[_\\s]*markets', 'IG Markets API Key'),
    ('cmc[_\\s]*markets', 'CMC Markets API Key'),
    # Crypto / digital assets
    ('coinmarketcap|cmc[_\\s]*api', 'CoinMarketCap API Key'),
    ('coingecko', 'CoinGecko API Key'),
    ('coinapi', 'CoinAPI Key'),
    ('messari', 'Messari API Key'),
    ('amberdata', 'Amberdata API Key'),
    ('kaiko', 'Kaiko API Key'),
    ('glassnode', 'Glassnode API Key'),
    ('cryptocompare', 'CryptoCompare API Key'),
    ('binance', 'Binance API Key'),
    ('kraken', 'Kraken API Key'),
    ('coinbase', 'Coinbase API Key'),
    ('bitfinex', 'Bitfinex API Key'),
    ('bybit', 'Bybit API Key'),
    ('kucoin', 'KuCoin API Key'),
    ('okx|okex', 'OKX API Key'),
    ('gemini(?:[_\\s]*exchange)?', 'Gemini Exchange API Key'),
    ('bitstamp', 'Bitstamp API Key'),
    ('cryptocom|crypto[_\\s]*com', 'Crypto.com API Key'),
    ('blockchain[_\\s]*info|blockchain[_\\s]*com', 'Blockchain.com API Key'),
    ('etherscan', 'Etherscan API Key'),
    ('bscscan', 'BscScan API Key'),
    ('polygonscan', 'PolygonScan API Key'),
    ('moralis', 'Moralis API Key'),
    ('alchemy(?:[_\\s]*api)?', 'Alchemy API Key'),
    ('infura', 'Infura API Key'),
    ('quicknode', 'QuickNode API Key'),
    # News / media intelligence
    ('newsapi|news[_\\s]*api', 'NewsAPI Key'),
    ('gnews', 'GNews API Key'),
    ('mediastack', 'Mediastack API Key'),
    ('currents[_\\s]*api|currentsapi', 'Currents API Key'),
    ('nytimes|nyt[_\\s]*api', 'NY Times API Key'),
    ('guardian(?:[_\\s]*api)?', 'Guardian API Key'),
    ('bing[_\\s]*news', 'Bing News API Key'),
    ('contextualweb', 'ContextualWeb API Key'),
    ('aylien', 'Aylien API Key'),
    ('event[_\\s]*registry', 'Event Registry API Key'),
    ('newsdata(?:[_\\s]*io)?', 'NewsData.io API Key'),
    ('world[_\\s]*news[_\\s]*api', 'World News API Key'),
    ('associated[_\\s]*press|ap[_\\s]*news', 'Associated Press API Key'),
    ('reuters', 'Reuters API Key'),
    ('diffbot', 'Diffbot API Key'),
    ('newscatcher', 'NewsCatcher API Key'),
    ('webz(?:[_\\s]*io)?|webhose', 'Webz.io API Key'),
    ('perigon', 'Perigon API Key'),
    ('contify', 'Contify API Key'),
    ('stream[_\\s]*publishers', 'Stream Publishers API Key'),
    ('mediacloud', 'MediaCloud API Key'),
    ('newslit', 'Newslit API Key'),
    ('zenrows', 'ZenRows API Key'),
    ('scrapingbee', 'ScrapingBee API Key'),
    ('scrapingdog', 'ScrapingDog API Key'),
    ('bright[_\\s]*data|luminati', 'Bright Data API Key'),
    ('serpapi', 'SerpAPI Key'),
    ('newsapi\\.ai', 'NewsAPI.ai Key'),
    ('lexisnexis', 'LexisNexis API Key'),
    ('factiva', 'Factiva API Key'),
    ('gdelt', 'GDELT API Key'),
    ('opensecrets', 'OpenSecrets API Key'),
    # Sports
    ('sportradar', 'Sportradar API Key'),
    ('api[_\\s-]*football', 'API-Football Key'),
    ('thesportsdb|sportsdb', 'TheSportsDB API Key'),
    ('odds[_\\s]*api', 'The Odds API Key'),
    ('espn', 'ESPN API Key'),
    ('football[_\\s-]*data', 'Football-Data API Key'),
    ('strava', 'Strava API Key'),
    ('sportsdata(?:[_\\s]*io)?', 'SportsData.io API Key'),
    ('balldontlie', 'BALLDONTLIE API Key'),
    ('pandascore|panda[_\\s]*score', 'PandaScore API Key'),
    ('sportmonks', 'Sportmonks API Key'),
    ('api[_\\s-]*basketball', 'API-Basketball Key'),
    ('api[_\\s-]*nba', 'API-NBA Key'),
    ('api[_\\s-]*hockey', 'API-Hockey Key'),
    ('api[_\\s-]*tennis', 'API-Tennis Key'),
    ('api[_\\s-]*rugby', 'API-Rugby Key'),
    ('api[_\\s-]*volleyball', 'API-Volleyball Key'),
    ('api[_\\s-]*mma', 'API-MMA Key'),
    ('api[_\\s-]*formula[_\\s-]*1|api[_\\s-]*f1', 'API-Formula1 Key'),
    ('api[_\\s-]*baseball', 'API-Baseball Key'),
    ('api[_\\s-]*handball', 'API-Handball Key'),
    ('goalserve', 'Goalserve API Key'),
    ('mysportsfeeds', 'MySportsFeeds API Key'),
    ('statpal', 'StatPal API Key'),
    ('sporting[_\\s]*life', 'Sporting Life API Key'),
    ('sofascore', 'SofaScore API Key'),
    ('stats[_\\s]*perform', 'Stats Perform API Key'),
    ('genius[_\\s]*sports', 'Genius Sports API Key'),
    ('sportingbet', 'Sportingbet API Key'),
    ('betfair', 'Betfair API Key'),
    ('pinnacle', 'Pinnacle API Key'),
    ('draftkings', 'DraftKings API Key'),
    ('fanduel', 'FanDuel API Key'),
    # Weather / climate
    ('openweathermap|open[_\\s]*weather', 'OpenWeatherMap API Key'),
    ('weatherapi|weather[_\\s]*api', 'WeatherAPI Key'),
    ('accuweather', 'AccuWeather API Key'),
    ('tomorrow\\.io|climacell', 'Tomorrow.io API Key'),
    ('weatherbit', 'Weatherbit API Key'),
    ('visual[_\\s]*crossing', 'Visual Crossing API Key'),
    ('dark[_\\s]*sky', 'Dark Sky API Key'),
    ('meteomatics', 'Meteomatics API Key'),
    ('weatherstack', 'Weatherstack API Key'),
    ('aerisweather|aeris', 'AerisWeather API Key'),
    ('stormglass', 'Stormglass API Key'),
    ('meteostat', 'Meteostat API Key'),
    # Maps / geo / location
    ('mapbox', 'Mapbox API Key'),
    ('here(?:[_\\s]*api)?', 'HERE API Key'),
    ('tomtom', 'TomTom API Key'),
    ('opencagedata|open[_\\s]*cage', 'OpenCage API Key'),
    ('positionstack', 'Positionstack API Key'),
    ('ipinfo|ipstack|ipgeolocation|ip[_\\s]*api', 'IP Geolocation API Key'),
    ('google[_\\s]*maps|maps[_\\s]*api', 'Google Maps API Key'),
    ('mapquest', 'MapQuest API Key'),
    ('what3words', 'what3words API Key'),
    ('geonames', 'GeoNames API Key'),
    ('foursquare', 'Foursquare API Key'),
    ('yelp', 'Yelp API Key'),
    ('tripadvisor', 'Tripadvisor API Key'),
    # Social / comms / productivity
    ('twitter|x[_\\s]*api', 'Twitter/X API Key'),
    ('reddit', 'Reddit API Key'),
    ('facebook|meta[_\\s]*api', 'Facebook/Meta API Key'),
    ('instagram', 'Instagram API Key'),
    ('linkedin', 'LinkedIn API Key'),
    ('tiktok', 'TikTok API Key'),
    ('youtube(?:[_\\s]*api)?', 'YouTube API Key'),
    ('spotify', 'Spotify API Key'),
    ('twitch', 'Twitch API Key'),
    ('discord', 'Discord API Key'),
    ('slack', 'Slack API Key'),
    ('telegram', 'Telegram Bot API Key'),
    ('sendgrid', 'SendGrid API Key'),
    ('mailgun', 'Mailgun API Key'),
    ('twilio', 'Twilio API Key'),
    ('postmark', 'Postmark API Key'),
    ('mailchimp', 'Mailchimp API Key'),
    ('hubspot', 'HubSpot API Key'),
    ('salesforce', 'Salesforce API Key'),
    ('zendesk', 'Zendesk API Key'),
    ('intercom', 'Intercom API Key'),
    ('pusher', 'Pusher API Key'),
    ('ably', 'Ably API Key'),
    ('pubnub', 'PubNub API Key'),
    ('rapidapi', 'RapidAPI Key'),
]

BASE_PATTERNS = [
    # LLM / AI providers — specific prefixes before generic sk-
    (re.compile(r'\bsk-ant-(?:api\d{2}-)?[a-zA-Z0-9_-]{20,}\b'), 'Anthropic API Key'),
    (re.compile(r'\bsk-or-v1-[a-zA-Z0-9_-]{20,}\b'), 'OpenRouter API Key'),
    (re.compile(r'\bsk-proj-[a-zA-Z0-9_-]{20,}\b'), 'OpenAI Project API Key'),
    (re.compile(r'\bsk-live-[a-zA-Z0-9_-]{20,}\b'), 'OpenAI Live API Key'),
    (re.compile(r'\bgsk_[a-zA-Z0-9]{20,}\b'), 'Groq API Key'),
    (re.compile(r'\bhf_[a-zA-Z0-9]{20,}\b'), 'Hugging Face API Key'),
    (re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), 'Google API Key'),
    (re.compile(r'\br8_[a-zA-Z0-9]{20,}\b'), 'Replicate API Key'),
    (re.compile(r'\bxai-[a-zA-Z0-9_-]{20,}\b'), 'xAI API Key'),
    (re.compile(r'\bpplx-[a-zA-Z0-9_-]{20,}\b'), 'Perplexity API Key'),
    (re.compile(r'\bfw_[a-zA-Z0-9_-]{20,}\b'), 'Fireworks API Key'),
    (re.compile(r'(?i)together[_\s]*api[_\s]*key\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?'), 'Together AI API Key'),
    (re.compile(r'(?i)cohere[_\s]*api[_\s]*key\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?'), 'Cohere API Key'),
    (re.compile(r'(?i)mistral[_\s]*api[_\s]*key\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?'), 'Mistral API Key'),
    (re.compile(r'(?i)deepseek[_\s]*api[_\s]*key\s*[:=]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?'), 'DeepSeek API Key'),
    (re.compile(r'\bsk-[a-zA-Z0-9_-]{20,}\b'), 'OpenAI API Key'),

    (re.compile(r'\btoken\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b'), 'Generic Token'),
    (re.compile(r'\bapi[_-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b'), 'API Key'),
    (re.compile(r'\bauth[_-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b'), 'Auth Key'),
    (re.compile(r'\bsecret[_-]?key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b'), 'Secret Key'),
    (re.compile(r'\boidc[_-]?token\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b', re.IGNORECASE), 'OIDC Token'),
    (re.compile(r'\bjwt[_-]?token\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b', re.IGNORECASE), 'JWT Token'),

    (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'AWS Access Key ID'),
    (re.compile(r'(?i)aws[_\s]*secret[_\s]*access[_\s]*key[^\w\n]*[\'"]?([A-Za-z0-9/+=]{40})'), 'AWS Secret Access Key'),

    (re.compile(r'\b(?:password|passwd|pass|pwd)\s*[:=]\s*[\'"]?([a-zA-Z0-9@#$%^&*()\-_=+!]{8,})[\'"]?\b'), 'Password'),

    (re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'), 'Email Address'),

    (re.compile(r'\b(?:ssh-(?:rsa|dss|ed25519)|ecdsa-[a-zA-Z0-9]+) [A-Za-z0-9+/=]+(?: [^\n]+)?\b'), 'SSH Key'),
    (re.compile(r'\b-----BEGIN [A-Z ]+-----[\s\S]+?-----END [A-Z ]+-----\b', re.DOTALL), 'Private Key'),

    (re.compile(r'\bmongodb\+srv://[^:]+:[^@]+@[^/]+/[^?]+\b'), 'MongoDB Connection String'),
    (re.compile(r'\bmysql:\/\/[^:]+:[^@]+@[^/]+/[^?]+\b'), 'MySQL Connection String'),
    (re.compile(r'\bpostgresql:\/\/[^:]+:[^@]+@[^/]+/[^?]+\b'), 'PostgreSQL Connection String'),

    (re.compile(r'\b(?:smtp|mail)\s*[:=]\s*[\'"]?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[\'"]?\b'), 'SMTP Email'),
    (re.compile(r'(?i)(smtp_(username|user|password|pass|server|host|port))\s*[:=]\s*["\']?([^"\'\s]+)["\']?'), 'SMTP Credentials'),

    (re.compile(r'(?i)define\s*\(\s*[\'"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*\)'), 'wp-config.php Credentials'),
    (re.compile(r'(?i)\$mail->(Host|Username|Password|Port)\s*=\s*[\'"]([^\'"]+)[\'"]'), 'PHPMailer SMTP Credential'),
    (re.compile(r'(?i)\$config\[\'(username|password)\'\]\s*=\s*[\'"]([^\'"]+)[\'"]'), 'CodeIgniter Config Credential'),
    (re.compile(r'(?i)\$db_(host|user|pass|name)\s*=\s*[\'"]([^\'"]+)[\'"]'), 'PHP DB Config Variable'),

    # HTTP headers commonly used by data APIs
    (re.compile(r'(?i)x-rapidapi-key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?'), 'RapidAPI Header Key'),
    (re.compile(r'(?i)x-api-key\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})[\'"]?'), 'X-API-Key Header'),
    (re.compile(r'(?i)authorization\s*[:=]\s*Bearer\s+([a-zA-Z0-9_\-\.]{20,})'), 'Bearer Token'),
]

_LLM_ENV = _env([
    'ANTHROPIC_API_KEY', 'OPENROUTER_API_KEY', 'TOGETHER_API_KEY', 'GROQ_API_KEY',
    'HUGGINGFACE_API_KEY', 'HF_TOKEN', 'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'COHERE_API_KEY',
    'MISTRAL_API_KEY', 'REPLICATE_API_TOKEN', 'XAI_API_KEY', 'PERPLEXITY_API_KEY', 'OPENAI_API_KEY',
    'DEEPSEEK_API_KEY', 'FIREWORKS_API_KEY', 'AZURE_OPENAI_API_KEY',
], 'LLM Provider ENV Key')

_GENERIC_ENV = _env([
    'DB_USER', 'DB_PASSWORD', 'DB_HOST', 'DB_NAME', 'SMTP_HOST', 'SMTP_USERNAME',
    'SMTP_PASSWORD', 'API_KEY', 'SECRET_KEY',
], 'ENV Variable Credential')

_DATA_ENV = _env([
    'ALPHA_VANTAGE_API_KEY', 'POLYGON_API_KEY', 'FINNHUB_API_KEY', 'IEX_API_KEY', 'IEX_CLOUD_API_KEY',
    'TWELVE_DATA_API_KEY', 'MARKETSTACK_API_KEY', 'QUANDL_API_KEY', 'TIINGO_API_KEY', 'EODHD_API_KEY',
    'FMP_API_KEY', 'FINANCIAL_MODELING_PREP_API_KEY', 'INTRINIO_API_KEY', 'BARCHART_API_KEY',
    'TRADIER_API_KEY', 'BENZINGA_API_KEY', 'ALPACA_API_KEY', 'ALPACA_SECRET_KEY', 'XIGNITE_API_KEY',
    'TRADING_ECONOMICS_API_KEY', 'FRED_API_KEY', 'PLAID_CLIENT_ID', 'PLAID_SECRET', 'STRIPE_API_KEY',
    'STRIPE_SECRET_KEY', 'COINMARKETCAP_API_KEY', 'COINGECKO_API_KEY', 'COINAPI_KEY', 'BINANCE_API_KEY',
    'KRAKEN_API_KEY', 'COINBASE_API_KEY', 'NEWS_API_KEY', 'NEWSAPI_KEY', 'GNEWS_API_KEY',
    'MEDIASTACK_API_KEY', 'CURRENTS_API_KEY', 'NYT_API_KEY', 'GUARDIAN_API_KEY', 'NEWSDATA_API_KEY',
    'SPORTRADAR_API_KEY', 'API_FOOTBALL_KEY', 'ODDS_API_KEY', 'STRAVA_CLIENT_SECRET', 'STRAVA_ACCESS_TOKEN',
    'OPENWEATHER_API_KEY', 'OPENWEATHERMAP_API_KEY', 'WEATHER_API_KEY', 'ACCUWEATHER_API_KEY',
    'TOMORROW_IO_API_KEY', 'MAPBOX_ACCESS_TOKEN', 'MAPBOX_API_KEY', 'HERE_API_KEY', 'TOMTOM_API_KEY',
    'RAPIDAPI_KEY', 'TWITTER_API_KEY', 'TWITTER_BEARER_TOKEN', 'REDDIT_CLIENT_SECRET', 'SLACK_BOT_TOKEN',
    'DISCORD_BOT_TOKEN', 'TELEGRAM_BOT_TOKEN', 'SENDGRID_API_KEY', 'MAILGUN_API_KEY', 'TWILIO_AUTH_TOKEN',
    'YOUTUBE_API_KEY', 'SPOTIFY_CLIENT_SECRET', 'TWITCH_CLIENT_SECRET', 'HUBSPOT_API_KEY',
], 'Data Provider ENV Key')

_PROVIDER_PATTERNS = [_ctx(alias, label) for alias, label in _NAMED_PROVIDERS]

SECRET_PATTERNS = BASE_PATTERNS + _PROVIDER_PATTERNS + [_LLM_ENV, _GENERIC_ENV, _DATA_ENV]

DATA_API_LABELS = {label for _, label in _NAMED_PROVIDERS} | {
    'Data Provider ENV Key', 'RapidAPI Header Key', 'X-API-Key Header', 'Bearer Token',
}


def get_covered_secret_types():
    return [description for _, description in SECRET_PATTERNS]


def pattern_count():
    return len(SECRET_PATTERNS)