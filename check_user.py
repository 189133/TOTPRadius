import sqlite3

conn = sqlite3.connect('db/totp_radius.db')
c = conn.cursor()
c.execute('SELECT * FROM users WHERE username = ?', ('111',))
result = c.fetchone()
print(f"用户信息: {result}")
conn.close()
