import os
import sys
import json
import sqlite3
import secrets
import time
import hmac
import hashlib
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeSerializer
from jinja2 import DictLoader

# Import self-contained bundles packaged inside the api directory
try:
    from .data_bundle import SHOPS_DATA
except Exception:
    try:
        from data_bundle import SHOPS_DATA
    except Exception:
        SHOPS_DATA = []

try:
    from .templates_bundle import TEMPLATES
except Exception:
    try:
        from templates_bundle import TEMPLATES
    except Exception:
        TEMPLATES = {}

# Determine Base and Static folders
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, 'public', 'static') if os.path.exists(os.path.join(BASE_DIR, 'public', 'static')) else os.path.join(BASE_DIR, 'static')

# Initialize Flask app
app = Flask(__name__, static_folder=STATIC_DIR, static_url_path='/static')
app.url_map.strict_slashes = False
app.config['SECRET_KEY'] = os.environ.get('NANDN_SECRET_KEY') or 'nandn-secret-key-prod-2026'

# --- SECURITY & COOKIE ENHANCEMENTS ---
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_PATH'] = '/'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
if os.environ.get('VERCEL') or os.environ.get('HTTPS') == 'on':
    app.config['SESSION_COOKIE_SECURE'] = True

# --- PRE-SEEDED VERIFIED ACCOUNTS (Zero Cold-Start Failure) ---
PRE_SEEDED_USERS = {
    'admin@nandn.local': {
        'id': 1,
        'name': 'N&N Administrator',
        'email': 'admin@nandn.local',
        'password_hash': generate_password_hash('NandN@2026'),
        'role': 'admin'
    },
    'demo@nandn.local': {
        'id': 2,
        'name': 'Verified Buyer (Demo)',
        'email': 'demo@nandn.local',
        'password_hash': generate_password_hash('Demo@2026'),
        'role': 'user'
    },
    'sameer@nandn.local': {
        'id': 3,
        'name': 'M. Sameer (Admin)',
        'email': 'sameer@nandn.local',
        'password_hash': generate_password_hash('Sameer@2026'),
        'role': 'admin'
    }
}

# --- CLIENT-SIDE USER VAULT (Survives Serverless Container Restarts) ---
VAULT_COOKIE = 'nandn_user_vault'

def get_user_vault():
    raw = request.cookies.get(VAULT_COOKIE)
    if not raw:
        return {}
    try:
        s = URLSafeSerializer(app.config['SECRET_KEY'], salt='nandn-vault')
        return s.loads(raw)
    except Exception:
        return {}

def save_user_vault_response(response, vault):
    try:
        s = URLSafeSerializer(app.config['SECRET_KEY'], salt='nandn-vault')
        val = s.dumps(vault)
        response.set_cookie(
            VAULT_COOKIE,
            val,
            max_age=60 * 60 * 24 * 30,  # 30 days
            httponly=True,
            samesite='Lax',
            secure=(os.environ.get('VERCEL') == '1' or request.is_secure),
            path='/'
        )
    except Exception as e:
        print("Vault cookie error:", e)
    return response

# Brute-force rate limiting store
FAILED_ATTEMPTS = {}

def check_rate_limit(key, max_attempts=8, window_seconds=180):
    now = time.time()
    attempts = [t for t in FAILED_ATTEMPTS.get(key, []) if now - t < window_seconds]
    FAILED_ATTEMPTS[key] = attempts
    return len(attempts) < max_attempts

def record_failed_attempt(key):
    now = time.time()
    if key not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = []
    FAILED_ATTEMPTS[key].append(now)

def clear_failed_attempts(key):
    FAILED_ATTEMPTS.pop(key, None)

# --- CRYPTOGRAPHIC STATELESS CSRF PROTECTION ---
def get_csrf_token():
    t = str(int(time.time()))
    sig = hmac.new(app.config['SECRET_KEY'].encode(), t.encode(), hashlib.sha256).hexdigest()
    token = f"{t}:{sig}"
    try:
        session['_csrf_token'] = token
    except Exception:
        pass
    return token

app.jinja_env.globals['csrf_token'] = get_csrf_token

def verify_csrf():
    token = request.form.get('csrf_token', '').strip()
    if not token:
        return False
    # 1. Match session token if available
    sess_token = session.get('_csrf_token')
    if sess_token and secrets.compare_digest(token, sess_token):
        return True
    # 2. Match HMAC signature & timestamp (valid for 24 hours across containers)
    try:
        parts = token.split(':', 1)
        if len(parts) == 2:
            t_str, sig = parts
            expected = hmac.new(app.config['SECRET_KEY'].encode(), t_str.encode(), hashlib.sha256).hexdigest()
            if secrets.compare_digest(sig, expected):
                age = time.time() - int(t_str)
                if 0 <= age <= 86400:
                    return True
    except Exception:
        pass
    return False

# --- WSGI MIDDLEWARE FOR ROBUST VERCEL ROUTING ---
class VercelMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        # 1. Detect HTTPS on Vercel
        proto = environ.get('HTTP_X_FORWARDED_PROTO') or ('https' if environ.get('VERCEL') else None)
        if proto:
            environ['wsgi.url_scheme'] = proto

        # 2. Detect real host
        host = environ.get('HTTP_X_FORWARDED_HOST')
        if host:
            environ['HTTP_HOST'] = host

        # 3. Detect real path forwarded from Vercel edge
        candidates = [
            environ.get('HTTP_X_VERCEL_FORWARDED_PATH'),
            environ.get('HTTP_X_FORWARDED_URI'),
            environ.get('HTTP_X_ORIGINAL_URI'),
            environ.get('REQUEST_URI'),
            environ.get('RAW_URI'),
            environ.get('HTTP_X_MATCHED_PATH'),
        ]
        real_path = None
        for c in candidates:
            if c:
                # Preserve query string if attached in edge header
                if '?' in c:
                    path_part, query_part = c.split('?', 1)
                    if not environ.get('QUERY_STRING'):
                        environ['QUERY_STRING'] = query_part
                else:
                    path_part = c

                clean = path_part.strip()
                if clean and not clean.startswith('/api/index') and clean != '/api':
                    real_path = clean
                    break

        if real_path:
            environ['PATH_INFO'] = real_path
        else:
            path_info = environ.get('PATH_INFO', '')
            if path_info.startswith('/api/index/'):
                environ['PATH_INFO'] = path_info[len('/api/index'):]
            elif path_info == '/api/index':
                environ['PATH_INFO'] = '/'
            elif path_info.startswith('/api/'):
                environ['PATH_INFO'] = path_info[len('/api'):]
            elif path_info == '/api':
                environ['PATH_INFO'] = '/'

        environ['SCRIPT_NAME'] = ''
        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelMiddleware(app.wsgi_app)

# Local static file fallback
@app.route('/static/<path:filename>')
def serve_static_fallback(filename):
    for folder in [
        os.path.join(BASE_DIR, 'public', 'static'),
        os.path.join(BASE_DIR, 'static'),
    ]:
        if os.path.exists(os.path.join(folder, filename)):
            from flask import send_from_directory
            return send_from_directory(folder, filename)
    abort(404)

# Set resilient DictLoader with all embedded templates
if TEMPLATES:
    app.jinja_loader = DictLoader(TEMPLATES)

# Determine DB path (writable /tmp in serverless environment)
if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
    DB_PATH = '/tmp/nandn.db'
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DB_PATH = os.path.join(BASE_DIR, 'nandn.db')

def connect():
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        return db
    except sqlite3.OperationalError:
        db = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        db.row_factory = sqlite3.Row
        return db

def init_db():
    try:
        with connect() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT NOT NULL,market_area TEXT,address TEXT,phone TEXT,product_line TEXT,top_products TEXT,price_range TEXT,average_price TEXT,business_type TEXT,verification TEXT,product_image_name TEXT,photo1 TEXT,photo2 TEXT);''')

            count = db.execute('SELECT COUNT(*) FROM shops').fetchone()[0]
            if count == 0 and SHOPS_DATA:
                db.executemany('INSERT INTO shops VALUES (:id,:name,:market_area,:address,:phone,:product_line,:top_products,:price_range,:average_price,:business_type,:verification,:product_image_name,:photo1,:photo2)', SHOPS_DATA)

            # Seed pre-configured accounts into SQLite
            for u in PRE_SEEDED_USERS.values():
                if not db.execute('SELECT id FROM users WHERE email=?', (u['email'],)).fetchone():
                    db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', (u['name'], u['email'], u['password_hash'], u['role']))
    except Exception as e:
        print("init_db error:", e)

init_db()

# --- HYBRID USER LOOKUP (SQLite -> Pre-Seeded -> Client Vault) ---
def get_user_by_email(email):
    email = email.strip().lower()
    # 1. Check SQLite
    try:
        with connect() as db:
            row = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
            if row:
                return dict(row)
    except Exception:
        pass

    # 2. Check Pre-Seeded accounts
    if email in PRE_SEEDED_USERS:
        u = PRE_SEEDED_USERS[email]
        try:
            with connect() as db:
                if not db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                    db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', (u['name'], u['email'], u['password_hash'], u['role']))
        except Exception:
            pass
        return u

    # 3. Check client-side signed vault
    vault = get_user_vault()
    if email in vault:
        u = vault[email]
        try:
            with connect() as db:
                if not db.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone():
                    db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', (u['name'], u['email'], u['password_hash'], u['role']))
        except Exception:
            pass
        return u

    return None

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get('user_id'):
            flash('Please sign in to access this page.', 'info')
            return redirect(url_for('login', next=request.path))
        return fn(*a, **kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get('user_id'):
            flash('Please sign in with administrator credentials.', 'info')
            return redirect(url_for('login', next=request.path))
        if session.get('role') != 'admin':
            abort(403)
        return fn(*a, **kw)
    return wrapped

@app.context_processor
def globals_for_templates():
    return {'current_user': session.get('user_name'), 'user_role': session.get('role')}

# --- ROUTES ---

@app.route('/')
@app.route('/api')
@app.route('/api/index')
def index():
    try:
        with connect() as db:
            total = db.execute('SELECT COUNT(*) FROM shops').fetchone()[0]
            areas = db.execute('SELECT COUNT(DISTINCT market_area) FROM shops').fetchone()[0]
            featured = db.execute("SELECT id, name, market_area, product_line, top_products, price_range, photo2 FROM shops WHERE photo2 IS NOT NULL AND photo2 != '' LIMIT 4").fetchall()
    except Exception:
        total = 500
        areas = 20
        featured = []
    return render_template('index.html', total=total, areas=areas, featured_products=featured)

@app.route('/products')
def products():
    q = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    page = max(1, request.args.get('page', 1, type=int))
    per = 12

    where = ["photo2 IS NOT NULL AND photo2 != ''"]
    params = []

    if q:
        like = '%' + q + '%'
        where.append('(top_products LIKE ? OR product_line LIKE ? OR name LIKE ? OR market_area LIKE ?)')
        params += [like] * 4

    if category and category != 'All':
        if category == 'Bedsheets':
            where.append('(product_line LIKE "%Bedsheet%" OR top_products LIKE "%Bedsheet%")')
        elif category == 'Blankets':
            where.append('(product_line LIKE "%Blanket%" OR product_line LIKE "%Kambal%" OR top_products LIKE "%Blanket%" OR top_products LIKE "%Kambal%")')
        elif category == 'Comforters':
            where.append('(product_line LIKE "%Comforter%" OR top_products LIKE "%Comforter%" OR top_products LIKE "%Bridal%")')
        elif category == 'Quilts':
            where.append('(product_line LIKE "%Razai%" OR top_products LIKE "%Razai%" OR top_products LIKE "%Quilt%")')
        elif category == 'Cushions':
            where.append('(product_line LIKE "%Cushion%" OR top_products LIKE "%Cushion%" OR top_products LIKE "%Pillow%")')
        else:
            where.append('(product_line LIKE ? OR top_products LIKE ?)')
            params += ['%' + category + '%'] * 2

    clause = ' WHERE ' + ' AND '.join(where)
    with connect() as db:
        total = db.execute('SELECT COUNT(*) FROM shops' + clause, params).fetchone()[0]
        products_list = db.execute('SELECT id, name, market_area, phone, product_line, top_products, price_range, average_price, business_type, photo2 FROM shops' + clause + ' ORDER BY id LIMIT ? OFFSET ?', params + [per, (page - 1) * per]).fetchall()

    categories_list = ['All', 'Bedsheets', 'Blankets', 'Comforters', 'Quilts', 'Cushions']

    return render_template(
        'products.html',
        products=products_list,
        total=total,
        page=page,
        pages=max(1, (total + per - 1) // per),
        q=q,
        selected_category=category or 'All',
        categories=categories_list
    )

@app.route('/directory')
def directory():
    q = request.args.get('q', '').strip()
    area = request.args.get('area', '').strip()
    category = request.args.get('category', '').strip()
    page = max(1, request.args.get('page', 1, type=int))
    per = 12
    where = []
    params = []
    if q:
        like = '%' + q + '%'
        where.append('(name LIKE ? OR market_area LIKE ? OR address LIKE ? OR phone LIKE ? OR product_line LIKE ? OR top_products LIKE ?)')
        params += [like] * 6
    if area:
        where.append('market_area=?')
        params.append(area)
    if category:
        where.append('(product_line LIKE ? OR top_products LIKE ?)')
        params += ['%' + category + '%'] * 2
    clause = (' WHERE ' + ' AND '.join(where)) if where else ''
    with connect() as db:
        total = db.execute('SELECT COUNT(*) FROM shops' + clause, params).fetchone()[0]
        shops = db.execute('SELECT * FROM shops' + clause + ' ORDER BY id LIMIT ? OFFSET ?', params + [per, (page - 1) * per]).fetchall()
        areas = [r[0] for r in db.execute("SELECT DISTINCT market_area FROM shops WHERE market_area IS NOT NULL AND market_area!='' ORDER BY market_area")]
        categories = [r[0] for r in db.execute("SELECT DISTINCT product_line FROM shops WHERE product_line IS NOT NULL AND product_line!='' ORDER BY product_line")]
    return render_template('directory.html', shops=shops, total=total, page=page, pages=max(1, (total + per - 1) // per), q=q, area=area, category=category, areas=areas, categories=categories)

@app.route('/shop/<int:shop_id>')
def shop_detail(shop_id):
    with connect() as db:
        shop = db.execute('SELECT * FROM shops WHERE id=?', (shop_id,)).fetchone()
        if not shop:
            abort(404)
        related = db.execute(
            'SELECT id, name, market_area, product_line, top_products, price_range, photo2 FROM shops WHERE (product_line=? OR market_area=?) AND id!=? LIMIT 4',
            (shop['product_line'], shop['market_area'], shop_id)
        ).fetchall()
        if not related:
            related = db.execute(
                'SELECT id, name, market_area, product_line, top_products, price_range, photo2 FROM shops WHERE id!=? LIMIT 4',
                (shop_id,)
            ).fetchall()
    return render_template('shop.html', shop=shop, related=related)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('directory'))

    if request.method == 'POST':
        if not verify_csrf():
            flash('Security session expired. Please refresh and try again.', 'error')
            return redirect(url_for('register'))

        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        pw = request.form.get('password', '')
        confirm = request.form.get('confirm', '')

        if not name or len(name) > 100 or not email or len(email) > 180 or '@' not in email:
            flash('Please enter a valid name and email address.', 'error')
        elif len(pw) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        elif pw != confirm:
            flash('Passwords do not match.', 'error')
        elif get_user_by_email(email):
            flash('An account with that email already exists.', 'error')
        else:
            try:
                pw_hash = generate_password_hash(pw)
                user_id = None
                with connect() as db:
                    cur = db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)', (name, email, pw_hash, 'user'))
                    user_id = cur.lastrowid

                # Save into signed vault so account persists across serverless restarts
                vault = get_user_vault()
                vault[email] = {
                    'id': user_id or int(time.time()),
                    'name': name,
                    'email': email,
                    'password_hash': pw_hash,
                    'role': 'user'
                }

                # Auto-login upon registration
                session.clear()
                session['user_id'] = vault[email]['id']
                session['user_name'] = name
                session['role'] = 'user'
                session.permanent = True

                flash(f'Account created successfully! Welcome to N&N Textile Directory, {name}.', 'success')
                resp = redirect(url_for('directory'))
                return save_user_vault_response(resp, vault)
            except sqlite3.IntegrityError:
                flash('An account with that email already exists.', 'error')
            except Exception as e:
                print("Registration error:", e)
                flash('Registration error. Please try again.', 'error')

    return render_template('auth.html', mode='register')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('directory'))

    if request.method == 'POST':
        if not verify_csrf():
            flash('Security session expired. Please refresh and try again.', 'error')
            return redirect(url_for('login'))

        email = request.form.get('email', '').strip().lower()
        pw = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        # Safe client IP rate limiting
        x_forwarded = request.headers.get('x-forwarded-for', '')
        client_ip = x_forwarded.split(',')[0].strip() if x_forwarded else (request.remote_addr or 'unknown')
        rate_key = f"{client_ip}:{email}"

        if not check_rate_limit(rate_key):
            flash('Too many failed attempts. For your security, please wait 3 minutes before trying again.', 'error')
            return render_template('auth.html', mode='login')

        user = get_user_by_email(email)
        if user and check_password_hash(user['password_hash'], pw):
            clear_failed_attempts(rate_key)
            session.clear()
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['role'] = user['role']
            session.permanent = bool(remember)

            flash(f'Signed in securely. Welcome back, {user["name"]}!', 'success')
            next_url = request.args.get('next') or request.form.get('next')
            if not next_url or not next_url.startswith('/') or next_url.startswith('//'):
                next_url = url_for('admin') if user['role'] == 'admin' else url_for('directory')
            return redirect(next_url)

        record_failed_attempt(rate_key)
        flash('Invalid email or password. Please verify your credentials.', 'error')

    return render_template('auth.html', mode='login')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    flash('You have signed out safely.', 'info')
    return redirect(url_for('index'))

@app.route('/admin')
@admin_required
def admin():
    with connect() as db:
        stats = {
            'shops': db.execute('SELECT COUNT(*) FROM shops').fetchone()[0],
            'users': db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        }
        users = db.execute('SELECT id,name,email,role,created_at FROM users ORDER BY id DESC LIMIT 20').fetchall()
        shops = db.execute('SELECT id,name,market_area,phone FROM shops ORDER BY id DESC LIMIT 20').fetchall()
    return render_template('admin.html', stats=stats, users=users, shops=shops)

@app.route('/admin/shop', methods=['POST'])
@admin_required
def add_shop():
    if not verify_csrf():
        flash('Security validation failed.', 'error')
        return redirect(url_for('admin'))
    d = {k: request.form.get(k, '').strip() for k in ['name', 'market_area', 'address', 'phone', 'product_line', 'top_products', 'price_range', 'average_price', 'business_type', 'verification']}
    if not d['name']:
        flash('Shop name is required.', 'error')
        return redirect(url_for('admin'))
    with connect() as db:
        nid = db.execute('SELECT COALESCE(MAX(id),0)+1 FROM shops').fetchone()[0]
        db.execute('INSERT INTO shops(id,name,market_area,address,phone,product_line,top_products,price_range,average_price,business_type,verification,product_image_name,photo1,photo2) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (nid, d['name'], d['market_area'], d['address'], d['phone'], d['product_line'], d['top_products'], d['price_range'], d['average_price'], d['business_type'], d['verification'], '', '', ''))
    flash('Shop added to the directory.', 'success')
    return redirect(url_for('directory'))

@app.route('/admin/shop/<int:shop_id>', methods=['GET', 'POST'])
@admin_required
def edit_shop(shop_id):
    keys = ['name', 'market_area', 'address', 'phone', 'product_line', 'top_products', 'price_range', 'average_price', 'business_type', 'verification']
    with connect() as db:
        shop = db.execute('SELECT * FROM shops WHERE id=?', (shop_id,)).fetchone()
    if not shop:
        abort(404)
    if request.method == 'POST':
        if not verify_csrf():
            flash('Security validation failed.', 'error')
            return redirect(url_for('edit_shop', shop_id=shop_id))
        d = {k: request.form.get(k, '').strip() for k in keys}
        if not d['name']:
            flash('Shop name is required.', 'error')
            return redirect(url_for('edit_shop', shop_id=shop_id))
        with connect() as db:
            db.execute('UPDATE shops SET name=?,market_area=?,address=?,phone=?,product_line=?,top_products=?,price_range=?,average_price=?,business_type=?,verification=? WHERE id=?', tuple(d[k] for k in keys) + (shop_id,))
        flash('Shop details updated.', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_shop.html', shop=shop)

@app.route('/admin/shop/<int:shop_id>/delete', methods=['POST'])
@admin_required
def delete_shop(shop_id):
    if not verify_csrf():
        flash('Security validation failed.', 'error')
        return redirect(url_for('admin'))
    with connect() as db:
        db.execute('DELETE FROM shops WHERE id=?', (shop_id,))
    flash('Shop record deleted.', 'info')
    return redirect(url_for('admin'))

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, message='This area is for administrators only.'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, message='We could not find that page or shop.'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
