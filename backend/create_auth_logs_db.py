import sqlite3
import os

# 数据库路径
db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db')
if not os.path.exists(db_dir):
    os.makedirs(db_dir)

db_path = os.path.join(db_dir, 'auth_logs.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 先删除旧表（如果存在）
c.execute('DROP TABLE IF EXISTS auth_logs')

# 创建认证记录表
c.execute('''
CREATE TABLE auth_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    protocol_type TEXT,
    nas_ip TEXT,
    server_ip TEXT,
    client_ip TEXT,
    nas_port_id TEXT,
    password TEXT,
    result TEXT NOT NULL,
    result_code INTEGER NOT NULL,
    error_message TEXT
)
''')

# 提交并关闭
conn.commit()
conn.close()

print(f"认证日志数据库创建成功: {db_path}")