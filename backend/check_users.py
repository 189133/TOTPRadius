import sqlite3

# 连接到数据库
conn = sqlite3.connect('totp_radius.db')
c = conn.cursor()

# 查询所有用户
print("=== 数据库中的用户信息 ===")
c.execute('SELECT * FROM users;')
users = c.fetchall()

if not users:
    print("数据库中没有用户！")
else:
    print(f"共找到 {len(users)} 个用户：")
    print("用户记录结构：")
    print("-" * 80)
    for i, user in enumerate(users):
        print(f"用户 {i+1}: {user}")
        print(f"字段数量: {len(user)}")
        print("-" * 80)

# 检查users表的结构
print("\n=== 表结构 ===")
c.execute('PRAGMA table_info(users);')
table_info = c.fetchall()
print("ID | 名称 | 类型 | 非空 | 默认值 | 主键")
print("-" * 80)
for col in table_info:
    print(f"{col[0]:2} | {col[1]:10} | {col[2]:15} | {col[3]:4} | {col[4]:8} | {col[5]:4}")

# 关闭连接
conn.close()

print("\n=== 检查完成 ===")