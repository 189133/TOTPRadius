import sqlite3
import os
import datetime

# 数据库路径
db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'db', 'auth_logs.db')

# 连接数据库
conn = sqlite3.connect(db_path)
c = conn.cursor()

# 查询第8和第9条记录
print("=== 认证日志第8和第9条记录 ===")
c.execute('SELECT id, username, timestamp, protocol_type, server_ip, client_ip, password, result, result_code, error_message FROM auth_logs WHERE id IN (8, 9) ORDER BY id ASC')
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
    record8 = records[0]  # 第8条记录
    record9 = records[1]  # 第9条记录
    
    # 解析时间
    time8 = datetime.datetime.strptime(record8[2], '%Y-%m-%d %H:%M:%S')
    time9 = datetime.datetime.strptime(record9[2], '%Y-%m-%d %H:%M:%S')
    
    # 计算时间差（秒）
    time_diff = (time9 - time8).total_seconds()
    print(f"时间差: {time_diff:.2f} 秒")
    
    # 检查12小时重连宽容条件
    print("\n12小时重连宽容条件检查:")
    print(f"- 相同用户名: {record8[1] == record9[1]}")
    print(f"- 相同协议类型: {record8[3] == record9[3]}")
    print(f"- 相同服务器IP: {record8[4] == record9[4]}")
    print(f"- 相同客户端IP: {record8[5] == record9[5]}")
    print(f"- 时间差<=43200秒: {time_diff <= 43200}")
    print(f"- 第8条记录成功: {record8[8] == 1000}")
    print(f"- 相同密码: {record8[6] == record9[6]}")
    
    # 检查10分钟最近认证宽容条件
    print("\n10分钟最近认证宽容条件检查:")
    print(f"- 相同用户名: {record8[1] == record9[1]}")
    print(f"- 相同协议类型: {record8[3] == record9[3]}")
    print(f"- 相同服务器IP: {record8[4] == record9[4]}")
    print(f"- 时间差<=600秒: {time_diff <= 600}")
    print(f"- 第8条记录成功: {record8[8] in (1000, 1001, 1002)}")
    print(f"- 相同密码: {record8[6] == record9[6]}")
    
    # 综合判断
    reconnect_tolerance = (record8[1] == record9[1] and 
                          record8[3] == record9[3] and 
                          record8[4] == record9[4] and 
                          record8[5] == record9[5] and 
                          time_diff <= 43200 and 
                          record8[8] == 1000 and 
                          record8[6] == record9[6])
    
    recent_tolerance = (record8[1] == record9[1] and 
                        record8[3] == record9[3] and 
                        record8[4] == record9[4] and 
                        time_diff <= 600 and 
                        record8[8] in (1000, 1001, 1002) and 
                        record8[6] == record9[6])
    
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