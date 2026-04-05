from flask import Flask, request, jsonify, send_from_directory, abort, make_response
from flask_cors import CORS
import sqlite3
import pyotp
import base64
import os
import logging
import datetime
import time

# 创建日志目录
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'log')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 生成日志文件名
log_date = datetime.datetime.now().strftime('%Y%m%d')
log_file = os.path.join(log_dir, f'web_{log_date}.log')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# 硬编码的HTTP认证信息
HTTP_USERNAME = 'gasadmin'
HTTP_PASSWORD = 'xxglb'

# 黑名单配置
MAX_FAILED_ATTEMPTS = 100  # 最大失败次数
LOCKOUT_DURATION = 300     # 锁定时间（秒）

# 黑名单和失败次数记录（内存中）
failed_attempts = {}  # {username: failed_count}
blacklist = {}        # {username: lockout_until_timestamp}

# HTTP认证中间件
@app.before_request
def http_auth():
    # 跳过静态文件和API验证路由
    if request.path.startswith('/static/') or request.path == '/api/verify':
        return
    
    # 获取认证信息
    auth = request.authorization
    if not auth or auth.username != HTTP_USERNAME or auth.password != HTTP_PASSWORD:
        logger.warning(f"HTTP认证失败: {request.remote_addr} 尝试访问 {request.path}")
        # 创建响应对象并添加WWW-Authenticate头，使浏览器弹出认证对话框
        response = make_response('请输入正确的用户名和密码', 401)
        response.headers['WWW-Authenticate'] = 'Basic realm="TOTP Radius Admin"'
        return response
    else:
        logger.info(f"HTTP认证成功: {request.remote_addr} 访问 {request.path}")

# 数据库路径
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db', 'totp_radius.db')

# 数据库初始化
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 totp_secret TEXT NOT NULL,
                 enabled INTEGER DEFAULT 1,
                 phone TEXT
                 )''')
    
    # 检查是否需要添加phone字段（针对已存在的数据库）
    c.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in c.fetchall()]
    if 'phone' not in columns:
        c.execute('ALTER TABLE users ADD COLUMN phone TEXT')
    
    # 创建配置表
    c.execute('''CREATE TABLE IF NOT EXISTS config (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 key TEXT UNIQUE NOT NULL,
                 value TEXT NOT NULL
                 )''')
    
    # 插入默认配置
    try:
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('debug_mode', '0'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('radius_secret', 'secotp'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('max_failed_attempts', '100'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('lockout_duration', '300'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('enable_reconnect_tolerance', '0'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('reconnect_tolerance_duration', '43200'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('enable_recent_tolerance', '0'))
        c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('recent_tolerance_duration', '600'))
    except sqlite3.IntegrityError:
        # 配置已存在，忽略
        pass
    
    conn.commit()
    conn.close()

# 初始化数据库
init_db()

# 从数据库中读取配置
def load_config():
    global MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT key, value FROM config')
        configs = c.fetchall()
        conn.close()
        
        for key, value in configs:
            if key == 'max_failed_attempts':
                MAX_FAILED_ATTEMPTS = int(value)
            elif key == 'lockout_duration':
                LOCKOUT_DURATION = int(value)
        
        logger.info(f"从数据库加载配置成功: MAX_FAILED_ATTEMPTS={MAX_FAILED_ATTEMPTS}, LOCKOUT_DURATION={LOCKOUT_DURATION}")
    except Exception as e:
        logger.error(f"加载配置失败: {e}")

# 加载配置
load_config()

# 黑名单相关函数
def is_user_blacklisted(username):
    """检查用户是否在黑名单中"""
    if username in blacklist:
        lockout_until = blacklist[username]
        if time.time() < lockout_until:
            return True
        else:
            # 锁定时间已过，从黑名单中移除
            del blacklist[username]
            logger.info(f"用户 {username} 已从黑名单中移除")
            return False
    return False

def add_to_blacklist(username):
    """添加用户到黑名单"""
    lockout_until = time.time() + LOCKOUT_DURATION
    blacklist[username] = lockout_until
    logger.warning(f"用户 {username} 已被添加到黑名单，锁定至 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lockout_until))}")

def record_failed_attempt(username):
    """记录认证失败"""
    if username not in failed_attempts:
        failed_attempts[username] = 0
    failed_attempts[username] += 1
    
    logger.warning(f"用户 {username} 认证失败次数: {failed_attempts[username]}/{MAX_FAILED_ATTEMPTS}")
    
    # 检查是否达到最大失败次数
    if failed_attempts[username] >= MAX_FAILED_ATTEMPTS:
        add_to_blacklist(username)
        # 清除失败次数
        del failed_attempts[username]

def clear_failed_attempts(username):
    """清除失败次数"""
    if username in failed_attempts:
        del failed_attempts[username]
        logger.info(f"用户 {username} 认证成功，失败次数已清除")

# 主页路由 - 返回前端界面
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# 获取用户列表
@app.route('/api/users', methods=['GET'])
def get_users():
    logger.info(f"获取用户列表: {request.remote_addr}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT id, username, enabled, phone FROM users')
    users = c.fetchall()
    conn.close()
    
    result = [{'id': user[0], 'username': user[1], 'enabled': bool(user[2]), 'phone': user[3]} for user in users]
    logger.info(f"获取用户列表成功，共 {len(result)} 个用户")
    return jsonify(result)

@app.route('/api/users', methods=['POST'])
def add_user():
    data = request.json
    username = data.get('username')
    phone = data.get('phone', '')
    
    logger.info(f"添加用户: {request.remote_addr} - {username}, phone: {phone}")
    
    if not username:
        logger.warning(f"添加用户失败: 缺少用户名")
        return jsonify({'error': 'Missing username'}), 400
    
    # 生成TOTP密钥
    totp_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, totp_secret, phone) VALUES (?, ?, ?)',
                  (username, totp_secret, phone))
        conn.commit()
        logger.info(f"添加用户成功: {username} (ID: {c.lastrowid})")
        return jsonify({'id': c.lastrowid, 'username': username, 'totp_secret': totp_secret, 'phone': phone}), 201
    except sqlite3.IntegrityError:
        logger.warning(f"添加用户失败: 用户名已存在 - {username}")
        return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    data = request.json
    enabled = data.get('enabled')
    phone = data.get('phone')
    
    logger.info(f"更新用户: {request.remote_addr} - ID: {user_id}, enabled: {enabled}, phone: {phone}")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        if enabled is not None:
            c.execute('UPDATE users SET enabled = ? WHERE id = ?', (enabled, user_id))
        if phone is not None:
            c.execute('UPDATE users SET phone = ? WHERE id = ?', (phone, user_id))
        conn.commit()
        if c.rowcount == 0:
            logger.warning(f"更新用户失败: 用户不存在 - ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        logger.info(f"更新用户成功: ID: {user_id}")
        return jsonify({'message': 'User updated successfully'})
    finally:
        conn.close()

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    logger.info(f"删除用户: {request.remote_addr} - ID: {user_id}")
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        if c.rowcount == 0:
            logger.warning(f"删除用户失败: 用户不存在 - ID: {user_id}")
            return jsonify({'error': 'User not found'}), 404
        logger.info(f"删除用户成功: ID: {user_id}")
        return jsonify({'message': 'User deleted successfully'})
    finally:
        conn.close()

# TOTP验证路由
@app.route('/api/verify', methods=['POST'])
def verify_totp():
    data = request.json
    username = data.get('username')
    totp_code = data.get('totp_code')
    
    logger.info(f"验证TOTP: {request.remote_addr} - {username}")
    
    if not username or not totp_code:
        logger.warning(f"验证TOTP失败: 缺少用户名或TOTP代码")
        return jsonify({'error': 'Missing username or totp code'}), 400
    
    # 检查用户是否在黑名单中
    if is_user_blacklisted(username):
        logger.warning(f"用户 {username} 在黑名单中，拒绝认证")
        return jsonify({'error': 'User is temporarily locked out'}), 401
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT totp_secret, enabled FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user or not user[1]:
        logger.warning(f"验证TOTP失败: 用户无效或已禁用 - {username}")
        # 记录失败尝试
        record_failed_attempt(username)
        return jsonify({'error': 'Invalid user or user disabled'}), 401
    
    # 验证TOTP代码
    totp = pyotp.TOTP(user[0])
    if not totp.verify(totp_code):
        # 认证失败，记录失败尝试
        record_failed_attempt(username)
        logger.warning(f"验证TOTP失败: 无效的TOTP代码 - {username}")
        return jsonify({'error': 'Invalid TOTP code'}), 401
    
    # 认证成功，清除失败次数
    clear_failed_attempts(username)
    logger.info(f"验证TOTP成功: {username}")
    return jsonify({'message': 'Authentication successful'})

# 配置管理路由
@app.route('/api/config', methods=['GET'])
def get_config():
    logger.info(f"获取配置: {request.remote_addr}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT key, value FROM config')
    configs = c.fetchall()
    conn.close()
    result = {config[0]: config[1] for config in configs}
    logger.info(f"获取配置成功")
    return jsonify(result)

@app.route('/api/config', methods=['POST'])
def update_config():
    data = request.json
    logger.info(f"更新配置: {request.remote_addr} - {data}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        for key, value in data.items():
            c.execute('INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)', (key, value))
        conn.commit()
        logger.info(f"更新配置成功")
        return jsonify({'message': 'Configuration updated successfully'})
    finally:
        conn.close()

if __name__ == '__main__':
    print("========================================")
    print("  TOTP Radius认证服务")
    print("========================================")
    print(f"前端界面: http://localhost:8080")
    print(f"API服务: http://localhost:8080/api")
    print(f"数据库: {DB_PATH}")
    print("========================================")
    print("按 Ctrl+C 停止服务器")
    print("========================================")
    app.run(debug=True, host='0.0.0.0', port=8080)
