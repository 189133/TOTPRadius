import sqlite3
import os

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'auth_logs.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 检查表结构
print("=== 认证日志数据库表结构 ===")
c.execute("PRAGMA table_info(auth_logs)")
columns = c.fetchall()
for col in columns:
    print(f"列名: {col[1]}, 类型: {col[2]}, 是否为空: {col[3]}, 默认值: {col[4]}")

# 检查是否存在result_code列
has_result_code = False
has_password = False
for col in columns:
    if col[1] == 'result_code':
        has_result_code = True
    if col[1] == 'password':
        has_password = True

print(f"\n是否存在result_code列: {has_result_code}")
print(f"是否存在password列: {has_password}")

# 关闭连接
conn.close()

print("\n检查完成！")