import json, os, sqlite3, secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
BASE_DIR=os.path.abspath(os.path.dirname(__file__))
DB_PATH=os.path.join(BASE_DIR,'nandn.db')
DATA_PATH=os.path.join(BASE_DIR,'shops.json')

if os.environ.get('VERCEL'):
    TMP_DB='/tmp/nandn.db'
    if not os.path.exists(TMP_DB) and os.path.exists(DB_PATH):
        try:
            import shutil
            shutil.copyfile(DB_PATH, TMP_DB)
        except Exception:
            pass
    DB_PATH=TMP_DB

STATIC_DIR=os.path.join(BASE_DIR,'public','static') if os.path.exists(os.path.join(BASE_DIR,'public','static')) else os.path.join(BASE_DIR,'static')
app=Flask(__name__, template_folder=os.path.join(BASE_DIR,'templates'), static_folder=STATIC_DIR, static_url_path='/static')
app.config['SECRET_KEY']=os.environ.get('NANDN_SECRET_KEY') or secrets.token_hex(32)
def connect():
    db=sqlite3.connect(DB_PATH); db.row_factory=sqlite3.Row; db.execute('PRAGMA foreign_keys=ON'); return db
def init_db():
    with connect() as db:
        db.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT 'user',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT NOT NULL,market_area TEXT,address TEXT,phone TEXT,product_line TEXT,top_products TEXT,price_range TEXT,average_price TEXT,business_type TEXT,verification TEXT,product_image_name TEXT,photo1 TEXT,photo2 TEXT);''')
        if db.execute('SELECT COUNT(*) FROM shops').fetchone()[0]==0:
            with open(DATA_PATH,encoding='utf-8') as f: data=json.load(f)
            db.executemany('INSERT INTO shops VALUES (:id,:name,:market_area,:address,:phone,:product_line,:top_products,:price_range,:average_price,:business_type,:verification,:product_image_name,:photo1,:photo2)',data)
        if not db.execute('SELECT id FROM users WHERE email=?',('admin@nandn.local',)).fetchone():
            db.execute('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)',('N&N Administrator','admin@nandn.local',generate_password_hash('NandN@2026'),'admin'))
init_db()
def login_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get('user_id'):
            flash('Please sign in to access the shop directory.','info'); return redirect(url_for('login',next=request.path))
        return fn(*a,**kw)
    return wrapped
def admin_required(fn):
    @wraps(fn)
    def wrapped(*a,**kw):
        if not session.get('user_id'): return redirect(url_for('login'))
        if session.get('role')!='admin': abort(403)
        return fn(*a,**kw)
    return wrapped
@app.context_processor
def globals_for_templates(): return {'current_user':session.get('user_name'),'user_role':session.get('role')}
@app.route('/')
def index():
    if session.get('user_id'): return redirect(url_for('directory'))
    with connect() as db:
        total=db.execute('SELECT COUNT(*) FROM shops').fetchone()[0]; areas=db.execute('SELECT COUNT(DISTINCT market_area) FROM shops').fetchone()[0]
    return render_template('index.html',total=total,areas=areas)
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        name=request.form.get('name','').strip(); email=request.form.get('email','').strip().lower(); pw=request.form.get('password',''); confirm=request.form.get('confirm','')
        if not name or len(name)>100 or not email or len(email)>180 or '@' not in email: flash('Please enter a valid name and email address.','error')
        elif len(pw)<8: flash('Password must be at least 8 characters long.','error')
        elif pw!=confirm: flash('Passwords do not match.','error')
        else:
            try:
                with connect() as db: db.execute('INSERT INTO users(name,email,password_hash) VALUES(?,?,?)',(name,email,generate_password_hash(pw)))
                flash('Account created. You can sign in now.','success'); return redirect(url_for('login'))
            except sqlite3.IntegrityError: flash('An account with that email already exists.','error')
    return render_template('auth.html',mode='register')
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower(); pw=request.form.get('password','')
        with connect() as db: user=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        if user and check_password_hash(user['password_hash'],pw):
            session.clear(); session['user_id']=user['id']; session['user_name']=user['name']; session['role']=user['role']; return redirect(url_for('directory'))
        flash('Email or password is incorrect.','error')
    return render_template('auth.html',mode='login')
@app.route('/logout',methods=['POST'])
def logout(): session.clear(); flash('You have signed out.','info'); return redirect(url_for('index'))
@app.route('/directory')
@login_required
def directory():
    q=request.args.get('q','').strip(); area=request.args.get('area','').strip(); category=request.args.get('category','').strip(); page=max(1,request.args.get('page',1,type=int)); per=12
    where=[]; params=[]
    if q:
        like='%'+q+'%'; where.append('(name LIKE ? OR market_area LIKE ? OR address LIKE ? OR phone LIKE ? OR product_line LIKE ? OR top_products LIKE ?)'); params += [like]*6
    if area: where.append('market_area=?'); params.append(area)
    if category: where.append('(product_line LIKE ? OR top_products LIKE ?)'); params += ['%'+category+'%']*2
    clause=(' WHERE '+' AND '.join(where)) if where else ''
    with connect() as db:
        total=db.execute('SELECT COUNT(*) FROM shops'+clause,params).fetchone()[0]
        shops=db.execute('SELECT * FROM shops'+clause+' ORDER BY id LIMIT ? OFFSET ?',params+[per,(page-1)*per]).fetchall()
        areas=[r[0] for r in db.execute("SELECT DISTINCT market_area FROM shops WHERE market_area IS NOT NULL AND market_area!='' ORDER BY market_area")]
        categories=[r[0] for r in db.execute("SELECT DISTINCT product_line FROM shops WHERE product_line IS NOT NULL AND product_line!='' ORDER BY product_line")]
    return render_template('directory.html',shops=shops,total=total,page=page,pages=max(1,(total+per-1)//per),q=q,area=area,category=category,areas=areas,categories=categories)
@app.route('/shop/<int:shop_id>')
@login_required
def shop_detail(shop_id):
    with connect() as db: shop=db.execute('SELECT * FROM shops WHERE id=?',(shop_id,)).fetchone()
    if not shop: abort(404)
    return render_template('shop.html',shop=shop)
@app.route('/admin')
@admin_required
def admin():
    with connect() as db:
        stats={'shops':db.execute('SELECT COUNT(*) FROM shops').fetchone()[0],'users':db.execute('SELECT COUNT(*) FROM users').fetchone()[0]}
        users=db.execute('SELECT id,name,email,role,created_at FROM users ORDER BY id DESC LIMIT 20').fetchall()
        shops=db.execute('SELECT id,name,market_area,phone FROM shops ORDER BY id DESC LIMIT 20').fetchall()
    return render_template('admin.html',stats=stats,users=users,shops=shops)
@app.route('/admin/shop',methods=['POST'])
@admin_required
def add_shop():
    d={k:request.form.get(k,'').strip() for k in ['name','market_area','address','phone','product_line','top_products','price_range','average_price','business_type','verification']}
    if not d['name']: flash('Shop name is required.','error'); return redirect(url_for('admin'))
    with connect() as db:
        nid=db.execute('SELECT COALESCE(MAX(id),0)+1 FROM shops').fetchone()[0]
        db.execute('INSERT INTO shops(id,name,market_area,address,phone,product_line,top_products,price_range,average_price,business_type,verification,product_image_name,photo1,photo2) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(nid,d['name'],d['market_area'],d['address'],d['phone'],d['product_line'],d['top_products'],d['price_range'],d['average_price'],d['business_type'],d['verification'],'','',''))
    flash('Shop added to the directory.','success'); return redirect(url_for('directory'))
@app.route('/admin/shop/<int:shop_id>',methods=['GET','POST'])
@admin_required
def edit_shop(shop_id):
    keys=['name','market_area','address','phone','product_line','top_products','price_range','average_price','business_type','verification']
    with connect() as db: shop=db.execute('SELECT * FROM shops WHERE id=?',(shop_id,)).fetchone()
    if not shop: abort(404)
    if request.method=='POST':
        d={k:request.form.get(k,'').strip() for k in keys}
        if not d['name']:
            flash('Shop name is required.','error'); return redirect(url_for('edit_shop',shop_id=shop_id))
        with connect() as db: db.execute('UPDATE shops SET name=?,market_area=?,address=?,phone=?,product_line=?,top_products=?,price_range=?,average_price=?,business_type=?,verification=? WHERE id=?',tuple(d[k] for k in keys)+(shop_id,))
        flash('Shop details updated.','success'); return redirect(url_for('admin'))
    return render_template('edit_shop.html',shop=shop)
@app.route('/admin/shop/<int:shop_id>/delete',methods=['POST'])
@admin_required
def delete_shop(shop_id):
    with connect() as db: db.execute('DELETE FROM shops WHERE id=?',(shop_id,))
    flash('Shop record deleted.','info'); return redirect(url_for('admin'))

@app.errorhandler(403)
def forbidden(e): return render_template('error.html',code=403,message='This area is for administrators only.'),403
@app.errorhandler(404)
def not_found(e): return render_template('error.html',code=404,message='We could not find that page or shop.'),404
if __name__=='__main__':
    app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),debug=False)
