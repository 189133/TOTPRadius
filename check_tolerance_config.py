import sqlite3
import os
import datetime

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'totp_radius.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 查询宽容认证配置
print("=== 宽容认证配置 ===")
c.execute('SELECT key, value FROM config WHERE key IN ("enable_reconnect_tolerance", "reconnect_tolerance_duration", "enable_recent_tolerance", "recent_tolerance_duration")')
configs = c.fetchall()

for key, value in configs:
    print(f"{key}: {value}")

# 关闭连接
conn.close()