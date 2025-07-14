# config.py
OS_AUTH_URL = "http://192.168.0.168:5000/v3"
OS_USER_DOMAIN_NAME = "Default"
OS_PROJECT_DOMAIN_NAME = "Default"
OS_PROJECT_NAME = "admin"
OS_USERNAME = "admin"
OS_PASSWORD = "adminpass"


# Database configuration
DB_CONFIG = {
    'host': '192.168.0.168',
    'user': 'keystone',
    'password': 'dbpass',
    'database': 'keystone',
     'port': 3306,  # Explicit port
    'connect_timeout': 5,
    'buffered': True  # For handling multiple results
}
