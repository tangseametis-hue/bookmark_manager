import os
# 強制拔除 Wireshark 留在系統中的環境變數干擾
os.environ.pop('SSLKEYLOGFILE', None)

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Bookmark

#修改前代码 敏感凭据泄露 / Session 伪造
"""app = Flask(__name__)
app.secret_key = 'bookmark_secret_secure_key'
# MySQL 連線設定
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost:3306/tag"""
#修改后代码1 避免代码上传到开源平台后泄露数据库账号密码；防止攻击者通过已知密钥伪造 Session 身份。
app = Flask(__name__)
# 优先从环境变量读取，若不存在则回退至硬编码默认值
app.secret_key = os.getenv('SECRET_KEY', 'bookmark_secret_secure_key')
# MySQL 連線設定
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'mysql+pymysql://root:root@localhost:3306/tag')


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#修改前代码 跨站请求伪造 (CSRF)
"""db.init_app(app)"""
#修改后代码2 确保所有新增、修改、删除操作均来自用户在你自己网页上的真实点击，防止钓鱼网站或恶意链接在用户不知情时伪造请求。
db.init_app(app)
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
# Cookie 安全增强设置
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


# ==================== 用戶模組 ====================

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # 檢查用戶是否已存在
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('用戶名或信箱已被註冊！', 'danger')
            return redirect(url_for('register'))

        # 密碼加密
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        flash('註冊成功，請登入！', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # 1. 基礎訊息寫入 Session 會話，保持登入狀態
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin  # 核心：將管理員狀態存入 session

            flash(f'歡迎回來，{user.username}！', 'success')

            # 2. 🔐 核心：管理員權限分流跳轉
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))

            # 普通用戶跳轉到個人首頁
            return redirect(url_for('index'))
        else:
            flash('用戶名或密碼錯誤！', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('您已成功登出！', 'info')
    return redirect(url_for('login'))


# ==================== 書籤模組 & 分頁搜尋 ====================

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    search_query = request.args.get('search', '')
    selected_tag = request.args.get('tag', '')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)

    query = Bookmark.query.filter_by(user_id=user_id)

    if search_query:
        query = query.filter(
            (Bookmark.title.like(f"%{search_query}%")) |
            (Bookmark.description.like(f"%{search_query}%")) |
            (Bookmark.tag.like(f"%{search_query}%"))
        )

    if selected_tag:
        query = query.filter_by(tag=selected_tag)

    pagination = query.order_by(Bookmark.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    bookmarks = pagination.items

    all_tags = db.session.query(Bookmark.tag).filter_by(user_id=user_id).distinct().all()
    tags = [t[0] for t in all_tags if t[0]]

    return render_template('index.html', bookmarks=bookmarks, pagination=pagination, tags=tags,
                           search_query=search_query, selected_tag=selected_tag, per_page=per_page)


@app.route('/bookmark/add', methods=['POST'])
def add_bookmark():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    title = request.form['title']
    #修改前代码4 XSS (跨站脚本攻击)
    '''url = request.form['url']'''
    #修改后代码4 拦截如 javascript:alert(1) 等伪协议链接，防止其他用户点击书签时触发恶意脚本。
    url = request.form['url'].strip()
    if not (url.startswith('http://') or url.startswith('https://')):
        flash('网路地址必须以 http:// 或 https:// 开头！', 'danger')
        return redirect(url_for('index'))
    description = request.form['description']
    tag = request.form['tag'].strip()

    if not title or not url:
        flash('標題與網址為必填欄位！', 'danger')
        return redirect(url_for('index'))

    new_bookmark = Bookmark(user_id=session['user_id'], title=title, url=url, description=description, tag=tag)
    db.session.add(new_bookmark)
    db.session.commit()
    flash('書籤添加成功！', 'success')
    return redirect(url_for('index'))


@app.route('/bookmark/edit/<int:id>', methods=['POST'])
def edit_bookmark(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bookmark = Bookmark.query.get_or_404(id)
    if bookmark.user_id != session['user_id']:
        flash('權限不足！', 'danger')
        return redirect(url_for('index'))

    bookmark.title = request.form['title']
    bookmark.url = request.form['url']
    bookmark.description = request.form['description']
    bookmark.tag = request.form['tag'].strip()

    db.session.commit()
    flash('書籤修改成功！', 'success')
    return redirect(url_for('index'))

#修改前代码3 CSRF / 链接预加载误删
'''@app.route('/bookmark/delete/<int:id>')
def delete_bookmark(id):'''
#修改后代码3 防止攻击者利用 <img> 或超链接诱导点击触发删除；防止浏览器预加载（Pre-fetching）插件自动访问 GET 删除链接导致数据丢失。
@app.route('/bookmark/delete/<int:id>', methods=['POST'])
def delete_bookmark(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    bookmark = Bookmark.query.get_or_404(id)
    if bookmark.user_id != session['user_id']:
        flash('權限不足！', 'danger')
        return redirect(url_for('index'))

    db.session.delete(bookmark)
    db.session.commit()
    flash('書籤已成功刪除！', 'success')
    return redirect(url_for('index'))


# ==================== ⭐ 新增：管理員模組 (已移至啟動前) ====================

@app.route('/admin')
def admin_dashboard():
    # 安全校驗：如果沒登入，或者登入了但不是管理員，拒絕訪問
    if 'user_id' not in session or not session.get('is_admin'):
        flash('權限不足，只有管理員可以訪問此頁面！', 'danger')
        return redirect(url_for('login'))

    # 撈出全站所有的用戶和全站所有的書籤
    all_users = User.query.all()
    all_bookmarks = Bookmark.query.all()

    return render_template('admin.html', users=all_users, bookmarks=all_bookmarks)

#修改前代码3
'''@app.route('/admin/delete_bookmark/<int:id>', methods=['POST', 'GET'])
def admin_delete_bookmark(id):'''
#修改后代码3
@app.route('/admin/delete_bookmark/<int:id>', methods=['POST'])
def admin_delete_bookmark(id):
    if 'user_id' not in session or not session.get('is_admin'):
        flash('權限不足！', 'danger')
        return redirect(url_for('login'))

    bookmark = Bookmark.query.get_or_404(id)
    db.session.delete(bookmark)
    db.session.commit()
    flash(f'管理員已成功刪除書籤：{bookmark.title}', 'success')
    return redirect(url_for('admin_dashboard'))


# ==================== 項目啟動核心 (必須放在最後) ====================
#修改前代码5 XSS 窃取 Cookie / CSRF远程代码执行 (RCE)
'''if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # 確保連線時自動建立資料表
    app.run(debug=True)'''
#修改后代码5 禁止前端 JavaScript 读取 Session Cookie，即使存在 XSS 漏洞，攻击者也无法直接盗取登录态；同时降低跨站请求携 Cookie 的风险。避免生产环境中报错时暴露复杂的代码堆栈和交互式调试控制台
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() in ['true', '1', 't']
    app.run(debug=debug_mode)
