import sqlite3
import os

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'totp_radius.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 查询所有配置
print("=== 数据库中的所有配置项 ===")
c.execute('SELECT key, value FROM config ORDER BY key')
configs = c.fetchall()

if configs:
    for key, value in configs:
        print(f"{key}: {value}")
else:
    print("数据库中没有配置项")

# 关闭连接
conn.close()