import socket
import struct
import hashlib
import time
import logging
import pyotp
import sqlite3
from pyrad import packet as pyrad_packet

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# RADIUS服务器配置
SERVER_ADDR = '127.0.0.1'
SERVER_PORT = 1812
SHARED_SECRET = b'secret'

# RADIUS属性代码
USER_NAME = 1
USER_PASSWORD = 2

# RADIUS消息类型
ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3

# 生成随机的request authenticator
def generate_authenticator():
    import os
    return os.urandom(16)

# 构建RADIUS认证请求
def build_access_request(username, password, secret):
    # 生成request authenticator
    authenticator = generate_authenticator()
    
    # 构建属性列表
    attributes = b''
    
    # 添加User-Name属性
    username_bytes = username.encode('utf-8')
    user_name_len = len(username_bytes) + 2  # 属性长度包括Type、Length和Value字段
    attributes += struct.pack('!B', USER_NAME) + struct.pack('!B', user_name_len) + username_bytes
    logger.info(f"添加User-Name属性: 代码={USER_NAME}, 长度={user_name_len}, 值={username}")
    
    # 添加User-Password属性（使用pyrad的PwCrypt方法加密）
    password_bytes = password.encode('utf-8')
    # 创建一个临时的AuthPacket对象来使用PwCrypt方法
    temp_pkt = pyrad_packet.AuthPacket(dict=None, secret=secret)
    temp_pkt.authenticator = authenticator  # 确保authenticator被正确设置
    encrypted_password = temp_pkt.PwCrypt(password_bytes)
    user_password_len = len(encrypted_password) + 2  # 属性长度包括Type、Length和Value字段
    attributes += struct.pack('!B', USER_PASSWORD) + struct.pack('!B', user_password_len) + encrypted_password
    logger.info(f"添加User-Password属性: 代码={USER_PASSWORD}, 长度={user_password_len}")
    
    # 构建RADIUS数据包
    code = ACCESS_REQUEST
    identifier = 1  # 简单起见，使用固定的identifier
    length = 20 + len(attributes)  # 20字节的头部 + 属性长度
    
    packet_data = struct.pack('!B', code) + struct.pack('!B', identifier) + struct.pack('!H', length) + authenticator + attributes
    
    # 打印数据包的十六进制表示
    logger.info(f"RADIUS数据包 (hex): {packet_data.hex()}")
    logger.info(f"RADIUS数据包长度: {len(packet_data)}")
    
    return packet_data, identifier, authenticator

# 发送认证请求并接收响应
def send_auth_request(username, password):
    print(f"=== 测试认证: {username} ===")
    
    # 创建UDP套接字
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)  # 设置5秒超时
    
    try:
        # 构建认证请求
        packet_data, identifier, authenticator = build_access_request(username, password, SHARED_SECRET)
        
        # 发送请求
        sock.sendto(packet_data, (SERVER_ADDR, SERVER_PORT))
        print("✅ 认证请求已发送")
        
        # 接收响应
        response, addr = sock.recvfrom(4096)
        print(f"✅ 收到响应来自: {addr}")
        
        # 解析响应
        if len(response) < 20:
            print("❌ 响应数据包太短")
            return False
        
        code = response[0]
        resp_identifier = response[1]
        length = struct.unpack('!H', response[2:4])[0]
        resp_authenticator = response[4:20]
        
        print(f"响应代码: {code}")
        print(f"响应标识符: {resp_identifier}")
        print(f"响应长度: {length}")
        
        if code == ACCESS_ACCEPT:
            print("🎉 认证成功! 服务器返回 Access-Accept")
            return True
        elif code == ACCESS_REJECT:
            print("❌ 认证失败! 服务器返回 Access-Reject")
            return False
        else:
            print(f"❓ 未知响应代码: {code}")
            return False
            
    except socket.timeout:
        print("❌ 超时: 服务器没有响应")
        return False
    except Exception as e:
        print(f"❌ 错误: {e}")
        return False
    finally:
        sock.close()

# 主测试函数
def main():
    print("=== RADIUS认证测试 ===")
    print("使用直接UDP套接字发送认证请求")
    print("自动计算TOTP验证码进行测试\n")
    
    # 从数据库获取用户"111"的TOTP密钥
    conn = sqlite3.connect('../db/totp_radius.db')
    c = conn.cursor()
    c.execute('SELECT totp_secret FROM users WHERE username = ?', ('111',))
    result = c.fetchone()
    conn.close()
    
    if not result:
        print("❌ 错误: 数据库中找不到用户 '111'")
        print("请先创建用户 '111'")
        return
    
    totp_secret = result[0]
    print(f"✅ 找到用户 '111'")
    print(f"   TOTP密钥: {totp_secret}")
    
    # 生成TOTP验证码
    totp = pyotp.TOTP(totp_secret)
    totp_code = totp.now()
    print(f"   生成的TOTP验证码: {totp_code}")
    print()
    
    username = "111"
    password = totp_code
    
    print("开始测试...")
    success = send_auth_request(username, password)
    
    print("\n=== 测试完成 ===")

if __name__ == "__main__":
    main()