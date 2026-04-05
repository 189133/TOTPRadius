import sqlite3
import pyotp

def test_auth_logic():
    print("=== 认证逻辑测试脚本 ===")
    print("\n请输入以下信息进行认证测试：")
    
    # 获取用户输入
    username = input("用户名: ")
    totp_code = input("TOTP验证码: ")
    
    try:
        # 连接数据库
        conn = sqlite3.connect('totp_radius.db')
        c = conn.cursor()
        
        # 查询用户信息
        print("\n查询用户信息...")
        c.execute('SELECT totp_secret, enabled FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if not user:
            print("❌ 认证失败：用户不存在")
            return
        
        if not user[1]:
            print("❌ 认证失败：用户已禁用")
            return
        
        # 验证TOTP代码
        print("验证TOTP验证码...")
        totp = pyotp.TOTP(user[0])
        
        if totp.verify(totp_code):
            print("✅ 认证成功！")
            print("TOTP验证码验证通过")
        else:
            print("❌ 认证失败：TOTP验证码错误")
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        print("请确保数据库文件存在并且结构正确")
    
    print("\n=== 测试完成 ===")

def list_users():
    print("=== 用户列表 ===")
    try:
        conn = sqlite3.connect('totp_radius.db')
        c = conn.cursor()
        c.execute('SELECT id, username, enabled FROM users')
        users = c.fetchall()
        conn.close()
        
        if not users:
            print("暂无用户，请先添加用户")
            return
        
        print("\nID  | 用户名  | 状态")
        print("--- | ------- | ----")
        for user in users:
            status = "启用" if user[2] else "禁用"
            print(f"{user[0]:3} | {user[1]:7} | {status}")
            
    except Exception as e:
        print(f"查询失败: {e}")

def main():
    while True:
        print("\n=== 认证测试工具 ===")
        print("1. 测试认证逻辑")
        print("2. 查看用户列表")
        print("3. 退出")
        
        choice = input("请选择操作 (1-3): ")
        
        if choice == "1":
            test_auth_logic()
        elif choice == "2":
            list_users()
        elif choice == "3":
            print("退出测试工具，再见！")
            break
        else:
            print("无效选择，请重新输入")

if __name__ == "__main__":
    main()