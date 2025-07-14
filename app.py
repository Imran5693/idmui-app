from flask import Flask, session
from keystone import bp as keystone_bp, format_bytes, format_number# Import blueprint from __init__.py
from keystone.utils import is_keystone_online

app = Flask(__name__)
app.secret_key = 'supersecretkey'

app.register_blueprint(keystone_bp, url_prefix='')

app.jinja_env.filters['format_bytes'] = format_bytes
app.jinja_env.filters['format_number'] = format_number

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
