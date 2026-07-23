import os
import re
import uuid
import sqlite3
import secrets
import logging
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, g, render_template, request, redirect, url_for,
    session, flash, abort, jsonify
)
from flask_socketio import SocketIO, emit, join_room
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from markupsafe import escape

# ---------------------------------------------------------------- 설정
DATABASE = 'market.db'
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
MAX_CONTENT_LENGTH = 3 * 1024 * 1024        # 3MB
REPORT_BLOCK_THRESHOLD = 3                   # 신고 누적 시 차단

app = Flask(__name__)

# [보안] SECRET_KEY 를 소스에 하드코딩하지 않고 환경변수에서 로드
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# [보안] 세션 쿠키 보호
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,             # JS 접근 차단 (XSS 탈취 방어)
    SESSION_COOKIE_SAMESITE='Lax',            # CSRF 완화
    SESSION_COOKIE_SECURE=bool(os.environ.get('HTTPS_ONLY')),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),   # 세션 만료
)

csrf = CSRFProtect(app)                       # [보안] 전역 CSRF 토큰 검증
limiter = Limiter(get_remote_address, app=app, default_limits=[])
socketio = SocketIO(app, cors_allowed_origins=[])   # [보안] CORS 화이트리스트

logging.basicConfig(
    filename='audit.log', level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)


# ---------------------------------------------------------------- DB
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        c = db.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS user (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT DEFAULT '',
            balance INTEGER NOT NULL DEFAULT 100000,
            is_admin INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'active',
            failed_login INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS product (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL,
            seller_id TEXT NOT NULL,
            image TEXT,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (seller_id) REFERENCES user(id)
        );
        CREATE TABLE IF NOT EXISTS report (
            id TEXT PRIMARY KEY,
            reporter_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            target_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(reporter_id, target_id)
        );
        CREATE TABLE IF NOT EXISTS transfer (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            memo TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS dm (
            id TEXT PRIMARY KEY,
            room TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_dm_room ON dm(room);
        CREATE INDEX IF NOT EXISTS idx_product_title ON product(title);
        """)
        db.commit()

        # 기본 관리자 계정 (환경변수로 비밀번호 지정)
        admin_pw = os.environ.get('ADMIN_PASSWORD', 'Admin!2345')
        c.execute("SELECT id FROM user WHERE username = ?", ('admin',))
        if not c.fetchone():
            c.execute(
                "INSERT INTO user (id, username, password, is_admin, bio) VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), 'admin',
                 generate_password_hash(admin_pw), 1, '관리자 계정')
            )
            db.commit()


# ---------------------------------------------------------------- 검증 유틸
USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,20}$')

def valid_username(u):
    return bool(u and USERNAME_RE.match(u))


def valid_password(p):
    """[보안] 최소 10자, 영문/숫자/특수문자 조합 강제"""
    if not p or len(p) < 10 or len(p) > 128:
        return False
    return (re.search(r'[A-Za-z]', p) and re.search(r'\d', p)
            and re.search(r'[^A-Za-z0-9]', p))


def clean_text(s, max_len):
    """[보안] 길이 제한 + 제어문자 제거. 출력은 Jinja2 자동 이스케이프로 XSS 방어"""
    if s is None:
        return ''
    s = str(s).strip()
    s = ''.join(ch for ch in s if ch == '\n' or ord(ch) >= 32)
    return s[:max_len]


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT


# ---------------------------------------------------------------- 인증 데코레이터
def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if 'user_id' not in session:
            flash('로그인이 필요합니다.')
            return redirect(url_for('login'))
        user = current_user()
        if user is None:
            session.clear()
            return redirect(url_for('login'))
        if user['status'] == 'dormant':
            session.clear()
            flash('신고 누적으로 휴면 처리된 계정입니다.')
            return redirect(url_for('login'))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*a, **kw):
        # [보안] 관리자 여부는 세션이 아닌 DB에서 매번 검증 (권한 상승 방지)
        if not current_user()['is_admin']:
            abort(403)
        return f(*a, **kw)
    return wrapper


def current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    cur = get_db().cursor()
    cur.execute("SELECT * FROM user WHERE id = ?", (uid,))
    return cur.fetchone()


@app.context_processor
def inject_globals():
    return dict(current_user=current_user(), csrf_token=generate_csrf)


# [보안] 클릭재킹/MIME 스니핑/XSS 방어 헤더
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; img-src 'self' data:; "
        "script-src 'self' https://cdn.socket.io; style-src 'self' 'unsafe-inline'"
    )
    return resp


# [보안] 에러 상세 노출 금지
@app.errorhandler(500)
def err500(e):
    logging.error(f"500 error: {e}")
    return render_template('error.html', msg='서버 오류가 발생했습니다.'), 500


@app.errorhandler(403)
def err403(e):
    return render_template('error.html', msg='권한이 없습니다.'), 403


@app.errorhandler(404)
def err404(e):
    return render_template('error.html', msg='페이지를 찾을 수 없습니다.'), 404


@app.errorhandler(413)
def err413(e):
    return render_template('error.html', msg='업로드 파일이 너무 큽니다.'), 413


# ---------------------------------------------------------------- 라우트: 기본
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per hour", methods=['POST'])
def register():
    if request.method == 'POST':
        username = clean_text(request.form.get('username'), 20)
        password = request.form.get('password') or ''
        password2 = request.form.get('password2') or ''

        if not valid_username(username):
            flash('아이디는 영문/숫자/_ 3~20자여야 합니다.')
            return redirect(url_for('register'))
        if password != password2:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('register'))
        if not valid_password(password):
            flash('비밀번호는 10자 이상이며 영문·숫자·특수문자를 포함해야 합니다.')
            return redirect(url_for('register'))

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT id FROM user WHERE username = ?", (username,))
        if cur.fetchone():
            flash('이미 존재하는 아이디입니다.')
            return redirect(url_for('register'))

        # [보안] 파라미터 바인딩으로 SQL Injection 방어, 비밀번호는 해시 저장
        cur.execute(
            "INSERT INTO user (id, username, password) VALUES (?,?,?)",
            (str(uuid.uuid4()), username, generate_password_hash(password))
        )
        db.commit()
        logging.info(f"register user={username}")
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per 5 minutes", methods=['POST'])   # [보안] 브루트포스 방어
def login():
    if request.method == 'POST':
        username = clean_text(request.form.get('username'), 20)
        password = request.form.get('password') or ''

        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM user WHERE username = ?", (username,))
        user = cur.fetchone()

        # [보안] 아이디/비밀번호 오류를 구분하지 않음 (계정 열거 방지)
        if not user or not check_password_hash(user['password'], password):
            if user:
                cur.execute(
                    "UPDATE user SET failed_login = failed_login + 1 WHERE id = ?",
                    (user['id'],))
                db.commit()
            logging.warning(f"login failed username={username}")
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))

        if user['status'] == 'dormant':
            flash('신고 누적으로 휴면 처리된 계정입니다.')
            return redirect(url_for('login'))

        cur.execute("UPDATE user SET failed_login = 0 WHERE id = ?", (user['id'],))
        db.commit()

        session.clear()                 # [보안] 세션 고정 공격 방어
        session.permanent = True
        session['user_id'] = user['id']
        logging.info(f"login success user={username}")
        return redirect(url_for('dashboard'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))


# ---------------------------------------------------------------- 상품
@app.route('/dashboard')
@login_required
def dashboard():
    q = clean_text(request.args.get('q'), 50)
    cur = get_db().cursor()
    if q:
        # [보안] LIKE 와일드카드 이스케이프 + 파라미터 바인딩
        pattern = '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        cur.execute(
            "SELECT p.*, u.username AS seller FROM product p JOIN user u ON p.seller_id=u.id "
            "WHERE p.status='active' AND (p.title LIKE ? ESCAPE '\\' OR p.description LIKE ? ESCAPE '\\') "
            "ORDER BY p.created_at DESC LIMIT 100", (pattern, pattern))
    else:
        cur.execute(
            "SELECT p.*, u.username AS seller FROM product p JOIN user u ON p.seller_id=u.id "
            "WHERE p.status='active' ORDER BY p.created_at DESC LIMIT 100")
    products = cur.fetchall()
    return render_template('dashboard.html', products=products, q=q)


@app.route('/product/new', methods=['GET', 'POST'])
@login_required
@limiter.limit("30 per hour", methods=['POST'])
def new_product():
    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 100)
        description = clean_text(request.form.get('description'), 2000)
        price_raw = request.form.get('price', '')

        if not title or not description:
            flash('상품명과 설명을 입력하세요.')
            return redirect(url_for('new_product'))
        # [보안] 숫자 형식/범위 검증 (음수 가격으로 잔액 증식 방지)
        if not re.fullmatch(r'\d{1,9}', price_raw or ''):
            flash('가격은 0 이상의 정수여야 합니다.')
            return redirect(url_for('new_product'))
        price = int(price_raw)

        filename = None
        file = request.files.get('image')
        if file and file.filename:
            if not allowed_file(file.filename):
                flash('허용되지 않는 이미지 형식입니다.')
                return redirect(url_for('new_product'))
            # [보안] 원본 파일명을 신뢰하지 않고 확장자만 취해 UUID로 재생성
            ext = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{uuid.uuid4().hex}.{ext}"
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'],
                                   secure_filename(filename)))

        db = get_db()
        db.execute(
            "INSERT INTO product (id, title, description, price, seller_id, image) "
            "VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), title, description, price,
             session['user_id'], filename))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')


@app.route('/product/<product_id>')
@login_required
def view_product(product_id):
    cur = get_db().cursor()
    cur.execute(
        "SELECT p.*, u.username AS seller FROM product p JOIN user u ON p.seller_id=u.id "
        "WHERE p.id = ?", (product_id,))
    product = cur.fetchone()
    if not product:
        abort(404)
    if product['status'] != 'active' and product['seller_id'] != session['user_id'] \
            and not current_user()['is_admin']:
        abort(404)
    return render_template('view_product.html', product=product)


@app.route('/product/<product_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cur.fetchone()
    if not product:
        abort(404)
    # [보안] IDOR 방어 - 소유자 또는 관리자만 수정 가능
    if product['seller_id'] != session['user_id'] and not current_user()['is_admin']:
        abort(403)

    if request.method == 'POST':
        title = clean_text(request.form.get('title'), 100)
        description = clean_text(request.form.get('description'), 2000)
        price_raw = request.form.get('price', '')
        if not title or not description or not re.fullmatch(r'\d{1,9}', price_raw or ''):
            flash('입력값을 확인하세요.')
            return redirect(url_for('edit_product', product_id=product_id))
        db.execute(
            "UPDATE product SET title=?, description=?, price=? WHERE id=?",
            (title, description, int(price_raw), product_id))
        db.commit()
        flash('상품이 수정되었습니다.')
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('edit_product.html', product=product)


@app.route('/product/<product_id>/delete', methods=['POST'])
@login_required
def delete_product(product_id):
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cur.fetchone()
    if not product:
        abort(404)
    if product['seller_id'] != session['user_id'] and not current_user()['is_admin']:
        abort(403)
    db.execute("DELETE FROM product WHERE id = ?", (product_id,))
    db.commit()
    logging.info(f"product deleted id={product_id} by={session['user_id']}")
    flash('상품이 삭제되었습니다.')
    return redirect(url_for('my_products'))


@app.route('/my/products')
@login_required
def my_products():
    cur = get_db().cursor()
    cur.execute("SELECT * FROM product WHERE seller_id=? ORDER BY created_at DESC",
                (session['user_id'],))
    return render_template('my_products.html', products=cur.fetchall())


# ---------------------------------------------------------------- 프로필
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    db = get_db()
    user = current_user()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'bio':
            bio = clean_text(request.form.get('bio'), 500)
            db.execute("UPDATE user SET bio=? WHERE id=?", (bio, user['id']))
            db.commit()
            flash('소개글이 수정되었습니다.')
        elif action == 'password':
            current_pw = request.form.get('current_password') or ''
            new_pw = request.form.get('new_password') or ''
            # [보안] 비밀번호 변경 시 현재 비밀번호 재확인
            if not check_password_hash(user['password'], current_pw):
                flash('현재 비밀번호가 올바르지 않습니다.')
                return redirect(url_for('profile'))
            if not valid_password(new_pw):
                flash('새 비밀번호는 10자 이상이며 영문·숫자·특수문자를 포함해야 합니다.')
                return redirect(url_for('profile'))
            db.execute("UPDATE user SET password=? WHERE id=?",
                       (generate_password_hash(new_pw), user['id']))
            db.commit()
            session.clear()          # [보안] 비밀번호 변경 후 재로그인 강제
            flash('비밀번호가 변경되었습니다. 다시 로그인하세요.')
            return redirect(url_for('login'))
        return redirect(url_for('profile'))
    return render_template('profile.html', user=user)


@app.route('/user/<user_id>')
@login_required
def view_user(user_id):
    cur = get_db().cursor()
    # [보안] 비밀번호 해시 등 민감정보는 SELECT 하지 않음
    cur.execute("SELECT id, username, bio, status, created_at FROM user WHERE id=?",
                (user_id,))
    user = cur.fetchone()
    if not user:
        abort(404)
    cur.execute("SELECT * FROM product WHERE seller_id=? AND status='active'", (user_id,))
    return render_template('view_user.html', user=user, products=cur.fetchall())


# ---------------------------------------------------------------- 송금
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour", methods=['POST'])
def transfer():
    db = get_db()
    me = current_user()
    if request.method == 'POST':
        to_username = clean_text(request.form.get('to_username'), 20)
        amount_raw = request.form.get('amount', '')
        memo = clean_text(request.form.get('memo'), 100)
        password = request.form.get('password') or ''

        # [보안] 송금 시 비밀번호 재확인 (세션 탈취 피해 최소화)
        if not check_password_hash(me['password'], password):
            flash('비밀번호가 올바르지 않습니다.')
            return redirect(url_for('transfer'))
        # [보안] 금액 정수/양수/상한 검증
        if not re.fullmatch(r'\d{1,9}', amount_raw or '') or int(amount_raw) <= 0:
            flash('송금액은 1 이상의 정수여야 합니다.')
            return redirect(url_for('transfer'))
        amount = int(amount_raw)

        cur = db.cursor()
        cur.execute("SELECT * FROM user WHERE username=?", (to_username,))
        receiver = cur.fetchone()
        if not receiver or receiver['id'] == me['id']:
            flash('받는 사람을 확인하세요.')
            return redirect(url_for('transfer'))
        if receiver['status'] != 'active':
            flash('휴면 계정으로는 송금할 수 없습니다.')
            return redirect(url_for('transfer'))

        try:
            # [보안] 트랜잭션 + 조건부 UPDATE 로 경쟁 조건(race condition) 방어
            cur.execute("BEGIN IMMEDIATE")
            cur.execute(
                "UPDATE user SET balance = balance - ? WHERE id=? AND balance >= ?",
                (amount, me['id'], amount))
            if cur.rowcount != 1:
                db.rollback()
                flash('잔액이 부족합니다.')
                return redirect(url_for('transfer'))
            cur.execute("UPDATE user SET balance = balance + ? WHERE id=?",
                        (amount, receiver['id']))
            cur.execute(
                "INSERT INTO transfer (id, sender_id, receiver_id, amount, memo) "
                "VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), me['id'], receiver['id'], amount, memo))
            db.commit()
        except sqlite3.Error:
            db.rollback()
            flash('송금 처리 중 오류가 발생했습니다.')
            return redirect(url_for('transfer'))

        logging.info(f"transfer {me['username']}->{to_username} {amount}")
        flash(f'{to_username}님에게 {amount}원을 송금했습니다.')
        return redirect(url_for('transfer'))

    cur = db.cursor()
    cur.execute(
        "SELECT t.*, s.username AS sender, r.username AS receiver FROM transfer t "
        "JOIN user s ON t.sender_id=s.id JOIN user r ON t.receiver_id=r.id "
        "WHERE t.sender_id=? OR t.receiver_id=? ORDER BY t.created_at DESC LIMIT 50",
        (me['id'], me['id']))
    return render_template('transfer.html', user=me, history=cur.fetchall())


# ---------------------------------------------------------------- 신고
@app.route('/report', methods=['GET', 'POST'])
@login_required
@limiter.limit("20 per hour", methods=['POST'])
def report():
    db = get_db()
    if request.method == 'POST':
        target_id = clean_text(request.form.get('target_id'), 64)
        target_type = request.form.get('target_type')
        reason = clean_text(request.form.get('reason'), 500)

        if target_type not in ('user', 'product') or not target_id or not reason:
            flash('신고 정보를 확인하세요.')
            return redirect(url_for('report'))

        cur = db.cursor()
        table = 'user' if target_type == 'user' else 'product'
        cur.execute(f"SELECT id FROM {table} WHERE id=?", (target_id,))
        if not cur.fetchone():
            flash('대상을 찾을 수 없습니다.')
            return redirect(url_for('report'))
        if target_id == session['user_id']:
            flash('자기 자신은 신고할 수 없습니다.')
            return redirect(url_for('report'))

        try:
            # [보안] UNIQUE 제약으로 동일인 중복 신고(신고 남용) 차단
            cur.execute(
                "INSERT INTO report (id, reporter_id, target_id, target_type, reason) "
                "VALUES (?,?,?,?,?)",
                (str(uuid.uuid4()), session['user_id'], target_id, target_type, reason))
            db.commit()
        except sqlite3.IntegrityError:
            flash('이미 신고한 대상입니다.')
            return redirect(url_for('report'))

        # 임계치 초과 시 자동 차단 / 휴면 전환
        cur.execute("SELECT COUNT(*) AS c FROM report WHERE target_id=?", (target_id,))
        if cur.fetchone()['c'] >= REPORT_BLOCK_THRESHOLD:
            if target_type == 'product':
                db.execute("UPDATE product SET status='blocked' WHERE id=?", (target_id,))
            else:
                db.execute("UPDATE user SET status='dormant' WHERE id=?", (target_id,))
            db.commit()
            logging.warning(f"auto-block {target_type} id={target_id}")

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html',
                           target_id=clean_text(request.args.get('target_id'), 64),
                           target_type=request.args.get('target_type', 'product'))


# ---------------------------------------------------------------- 1:1 채팅
def dm_room(a, b):
    return 'dm_' + '_'.join(sorted([a, b]))


@app.route('/dm/<user_id>')
@login_required
def direct_message(user_id):
    cur = get_db().cursor()
    cur.execute("SELECT id, username FROM user WHERE id=?", (user_id,))
    partner = cur.fetchone()
    if not partner or partner['id'] == session['user_id']:
        abort(404)
    room = dm_room(session['user_id'], user_id)
    # [보안] 대화 이력은 본인이 참여한 방만 조회 가능
    cur.execute(
        "SELECT d.*, u.username AS sender_name FROM dm d JOIN user u ON d.sender_id=u.id "
        "WHERE d.room=? AND (d.sender_id=? OR d.receiver_id=?) "
        "ORDER BY d.created_at ASC LIMIT 200",
        (room, session['user_id'], session['user_id']))
    return render_template('dm.html', partner=partner, room=room,
                           messages=cur.fetchall())


# ---------------------------------------------------------------- 관리자
@app.route('/admin')
@admin_required
def admin_dashboard():
    cur = get_db().cursor()
    cur.execute("SELECT id, username, status, balance, is_admin FROM user ORDER BY created_at DESC")
    users = cur.fetchall()
    cur.execute("SELECT p.*, u.username AS seller FROM product p JOIN user u ON p.seller_id=u.id "
                "ORDER BY p.created_at DESC")
    products = cur.fetchall()
    cur.execute("SELECT r.*, u.username AS reporter FROM report r "
                "JOIN user u ON r.reporter_id=u.id ORDER BY r.created_at DESC LIMIT 100")
    reports = cur.fetchall()
    return render_template('admin.html', users=users, products=products, reports=reports)


@app.route('/admin/user/<user_id>/<action>', methods=['POST'])
@admin_required
def admin_user_action(user_id, action):
    if action not in ('dormant', 'active'):
        abort(400)
    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT is_admin FROM user WHERE id=?", (user_id,))
    target = cur.fetchone()
    if not target:
        abort(404)
    # [보안] 관리자 계정은 휴면 처리 불가
    if target['is_admin']:
        flash('관리자 계정은 변경할 수 없습니다.')
        return redirect(url_for('admin_dashboard'))
    db.execute("UPDATE user SET status=? WHERE id=?", (action, user_id))
    db.commit()
    logging.info(f"admin set user={user_id} status={action}")
    flash('처리되었습니다.')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/product/<product_id>/<action>', methods=['POST'])
@admin_required
def admin_product_action(product_id, action):
    if action not in ('blocked', 'active', 'delete'):
        abort(400)
    db = get_db()
    if action == 'delete':
        db.execute("DELETE FROM product WHERE id=?", (product_id,))
    else:
        db.execute("UPDATE product SET status=? WHERE id=?", (action, product_id))
    db.commit()
    logging.info(f"admin product={product_id} action={action}")
    flash('처리되었습니다.')
    return redirect(url_for('admin_dashboard'))


# ---------------------------------------------------------------- WebSocket
@socketio.on('connect')
def ws_connect():
    # [보안] 인증되지 않은 소켓 연결 거부
    if 'user_id' not in session:
        return False
    user = current_user()
    if user is None or user['status'] != 'active':
        return False


@socketio.on('send_message')
def ws_send_message(data):
    if 'user_id' not in session:
        return
    user = current_user()
    if user is None or user['status'] != 'active':
        return
    # [보안] 클라이언트가 보낸 발신자명을 신뢰하지 않고 서버 세션에서 결정
    content = clean_text((data or {}).get('message'), 500)
    if not content:
        return
    emit('message', {
        'username': user['username'],
        'message': content            # 클라이언트에서 textContent로 삽입 → XSS 방어
    }, broadcast=True)


@socketio.on('join_dm')
def ws_join_dm(data):
    if 'user_id' not in session:
        return
    partner_id = clean_text((data or {}).get('partner_id'), 64)
    if not partner_id:
        return
    # [보안] 방 이름을 클라이언트가 아닌 서버에서 계산 → 임의 방 도청 차단
    join_room(dm_room(session['user_id'], partner_id))


@socketio.on('send_dm')
def ws_send_dm(data):
    if 'user_id' not in session:
        return
    me = current_user()
    if me is None or me['status'] != 'active':
        return
    partner_id = clean_text((data or {}).get('partner_id'), 64)
    content = clean_text((data or {}).get('message'), 500)
    if not partner_id or not content:
        return

    db = get_db()
    cur = db.cursor()
    cur.execute("SELECT id, status FROM user WHERE id=?", (partner_id,))
    partner = cur.fetchone()
    if not partner or partner['id'] == me['id']:
        return

    room = dm_room(me['id'], partner_id)
    db.execute(
        "INSERT INTO dm (id, room, sender_id, receiver_id, content) VALUES (?,?,?,?,?)",
        (str(uuid.uuid4()), room, me['id'], partner_id, content))
    db.commit()
    emit('dm_message', {'username': me['username'], 'message': content}, room=room)


if __name__ == '__main__':
    init_db()
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)   # [보안] debug=False
