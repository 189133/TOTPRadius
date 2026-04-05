import sqlite3
import os

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'totp_radius.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 添加宽容认证配置项
print("=== 添加宽容认证配置项 ===")
try:
    c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('max_failed_attempts', '100'))
    c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('lockout_duration', '300'))
    c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('enable_reconnect_tolerance', '1'))
    c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('reconnect_tolerance_duration', '43200'))
    c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('enable_recent_tolerance', '1'))
    c.execute('INSERT INTO config (key, value) VALUES (?, ?)', ('recent_tolerance_duration', '600'))
    conn.commit()
    print("配置项添加成功！")
except sqlite3.IntegrityError as e:
    print(f"配置项已存在: {e}")

# 查询所有配置
print("\n=== 当前的所有配置项 ===")
c.execute('SELECT key, value FROM config ORDER BY key')
configs = c.fetchall()

for key, value in configs:
    print(f"{key}: {value}")

# 关闭连接
conn.close()