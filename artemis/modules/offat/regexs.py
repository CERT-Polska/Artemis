sensitive_data_regex_patterns = {
    # General Data
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
    # 'passwordOrToken': r'(^|\s|")(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&_])[A-Za-z\d@$!%*#?&_]{10,}($|\s|")', # Assuming the password contains at least 1 uppercase letter, 1 lowercase letter, 1 digit, 1 special character, and is at least 8 characters long.
    'date': r'\b\d{2}/\d{2}/\d{4}\b',
    'ip': r'(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b',
    'ccn': r'\b\d{4}-\d{4}-\d{4}-\d{4}\b',
    'jwtToken': r'(^|\s|")[A-Za-z0-9_-]{2,}(?:\.[A-Za-z0-9_-]{2,}){2}($|\s|")',
    'ato_data': r'\b(auth_code|otp|password|password_hash|auth_token|access_token|refresh_token|secret|session_id|key|pin|accessToken|refreshToken|authenticationCode|authentication_code|jwt|api_secret|apiSecret)\b',
    # BRAZIL
    'BrazilCPF': r'\b(\d{3}\.){2}\d{3}\-\d{2}\b',
    # INDIA
    # Assuming the format: AAAAB1234C (5 uppercase letters, 4 digits, 1 uppercase letter)
    'pan': r'\b[A-Z]{5}\d{4}[A-Z]{1}\b',
    # Assuming the format XXXX XXXX XXXX (4 digits, space, 4 digits, space, 4 digits)
    'aadhaarCard': r'\b\d{4}\s\d{4}\s\d{4}\b',
    'PhoneNumberIN': r'\b((\+*)((0[ -]*)*|((91 )*))((\d{12})+|(\d{10})+))|\d{5}([- ]*)\d{6}\b',
    # US
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'PhoneNumberUS': r'\b(^|\s|")(1\s?)?(\d{3}|\(\d{3}\))[\s\-]?\d{3}[\s\-]?\d{4}(?:$|\s|")\b',
    # AWS
    # Assuming the format: AKIA followed by 16 uppercase alphanumeric characters
    'AWSAccessKey': r'\bAKIA[0-9A-Z]{16}\b',
    # Assuming the format: 40 alphanumeric characters, including + and /
    'AWSSecretKey': r'\b[0-9a-zA-Z/+]{40}\b',
    'AWSResourceURL': r'\b([A-Za-z0-9-_]*\.[A-Za-z0-9-_]*\.amazonaws.com*)\b',
    'AWSArnId': r'\barn:aws:[A-Za-z0-9-_]*\:[A-Za-z0-9-_]*\:[A-Za-z0-9-_]*\:[A-Za-z0-9-/_]*\b',
    # Google Tokens
    'Google' : r'google_oauth_token|google_oauth|google_b64',
    # Slack
    'Slack' : r'xoxo-[0-9a-z]+-[0-9a-z]+-[0-9a-z]+-[0-9a-z]+',
    # Postgres DSN postgresql://[user[:password]@][netloc][:port][/dbname][?param1=value1&...]
    'PostgresDSN' : r'postgresql:\/\/|pgsql:',
    'MySQLDSN' : 'mysql://',
    'RedisDSN' : 'redis://',
    'OutlookWebhook' : 'https://outlook.office.com/webhook/'
}
