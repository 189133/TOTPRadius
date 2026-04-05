import sqlite3
import os
import datetime

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'auth_logs.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 查询第10和第11条记录
print("=== 认证日志第10和第11条记录 ===")
c.execute('SELECT id, username, timestamp, protocol_type, server_ip, client_ip, password, result, result_code, error_message FROM auth_logs WHERE id IN (10, 11) ORDER BY id ASC')
records = c.fetchall()

for record in records:
    print(f"\n记录ID: {record[0]}")
    print(f"用户名: {record[1]}")
    print(f"时间: {record[2]}")
    print(f"协议类型: {record[3]}")
    print(f"服务器IP: {record[4]}")
    print(f"客户端IP: {record[5]}")
    print(f"密码: {record[6]}")
    print(f"结果: {record[7]}")
    print(f"结果代码: {record[8]}")
    print(f"错误信息: {record[9]}")

# 分析是否符合宽容认证条件
print("\n=== 宽容认证分析 ===")
if len(records) == 2:
    record10 = records[0]  # 第10条记录
    record11 = records[1]  # 第11条记录
    
    # 解析时间
    time10 = datetime.datetime.strptime(record10[2], '%Y-%m-%d %H:%M:%S')
    time11 = datetime.datetime.strptime(record11[2], '%Y-%m-%d %H:%M:%S')
    
    # 计算时间差（秒）
    time_diff = (time11 - time10).total_seconds()
    print(f"时间差: {time_diff:.2f} 秒")
    
    # 检查12小时重连宽容条件
    print("\n12小时重连宽容条件检查:")
    print(f"- 相同用户名: {record10[1] == record11[1]} ({record10[1]} == {record11[1]})")
    print(f"- 相同协议类型: {record10[3] == record11[3]} ({record10[3]} == {record11[3]})")
    print(f"- 相同服务器IP: {record10[4] == record11[4]} ({record10[4]} == {record11[4]})")
    print(f"- 相同客户端IP: {record10[5] == record11[5]} ({record10[5]} == {record11[5]})")
    print(f"- 时间差<=43200秒: {time_diff <= 43200} ({time_diff:.2f} <= 43200)")
    print(f"- 第10条记录成功: {record10[8] == 1000} (代码: {record10[8]})")
    print(f"- 相同密码: {record10[6] == record11[6]} ({record10[6]} == {record11[6]})")
    
    # 检查10分钟最近认证宽容条件
    print("\n10分钟最近认证宽容条件检查:")
    print(f"- 相同用户名: {record10[1] == record11[1]} ({record10[1]} == {record11[1]})")
    print(f"- 相同协议类型: {record10[3] == record11[3]} ({record10[3]} == {record11[3]})")
    print(f"- 相同服务器IP: {record10[4] == record11[4]} ({record10[4]} == {record11[4]})")
    print(f"- 时间差<=600秒: {time_diff <= 600} ({time_diff:.2f} <= 600)")
    print(f"- 第10条记录成功: {record10[8] in (1000, 1001, 1002)} (代码: {record10[8]})")
    print(f"- 相同密码: {record10[6] == record11[6]} ({record10[6]} == {record11[6]})")
    
    # 综合判断
    reconnect_tolerance = (record10[1] == record11[1] and 
                          record10[3] == record11[3] and 
                          record10[4] == record11[4] and 
                          record10[5] == record11[5] and 
                          time_diff <= 43200 and 
                          record10[8] == 1000 and 
                          record10[6] == record11[6])
    
    recent_tolerance = (record10[1] == record11[1] and 
                        record10[3] == record11[3] and 
                        record10[4] == record11[4] and 
                        time_diff <= 600 and 
                        record10[8] in (1000, 1001, 1002) and 
                        record10[6] == record11[6])
    
    print("\n=== 分析结果 ===")
    print(f"符合12小时重连宽容: {reconnect_tolerance}")
    print(f"符合10分钟最近认证宽容: {recent_tolerance}")
    
    if reconnect_tolerance:
        print("建议结果代码: 1001 (SUCCESS_RECONNECT)")
    elif recent_tolerance:
        print("建议结果代码: 1002 (SUCCESS_RECENT)")
    else:
        print("不符合宽容认证条件")
else:
    print("没有找到足够的记录")

# 关闭连接
conn.close()