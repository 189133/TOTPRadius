import os
from re import T
import sys
import sqlite3
import pyotp
import logging
import hashlib
import struct
import datetime

from pyrad import server, packet
from pyrad.dictionary import Dictionary

# 配置日志
import datetime
import os

# 创建日志目录
log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'log')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 生成日志文件名
log_date = datetime.datetime.now().strftime('%Y%m%d')
log_file = os.path.join(log_dir, f'radius_{log_date}.log')

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 数据库路径
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db', 'totp_radius.db')

# 认证日志数据库路径
AUTH_LOGS_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'db', 'auth_logs.db')

# 全局调试模式
DEBUG_MODE = True  # 调试模式下，任何密码验证都通过

# 全局共享密钥
RADIUS_SECRET = b'secotp'

# 黑名单配置
MAX_FAILED_ATTEMPTS = 100  # 最大失败次数
LOCKOUT_DURATION = 300     # 锁定时间（秒）

# 宽容认证配置
ENABLE_RECONNECT宽容 = False  # 是否开启12小时重连宽容
RECONNECT宽容_DURATION = 43200  # 12小时（秒）
ENABLE_RECENT宽容 = False  # 是否开启10分钟最近认证宽容
RECENT宽容_DURATION = 600  # 10分钟（秒）

# 黑名单和失败次数记录（内存中）
failed_attempts = {}  # {username: failed_count}
blacklist = {}        # {username: lockout_until_timestamp}

# 从数据库中读取配置
def load_config():
    global DEBUG_MODE, RADIUS_SECRET, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION
    global ENABLE_RECONNECT宽容, RECONNECT宽容_DURATION, ENABLE_RECENT宽容, RECENT宽容_DURATION
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT key, value FROM config')
        configs = c.fetchall()
        conn.close()
        
        for key, value in configs:
            if key == 'debug_mode':
                DEBUG_MODE = bool(int(value))
            elif key == 'radius_secret':
                RADIUS_SECRET = value.encode('utf-8')
            elif key == 'max_failed_attempts':
                MAX_FAILED_ATTEMPTS = int(value)
            elif key == 'lockout_duration':
                LOCKOUT_DURATION = int(value)
            elif key == 'enable_reconnect_tolerance':
                ENABLE_RECONNECT宽容 = bool(int(value))
            elif key == 'reconnect_tolerance_duration':
                RECONNECT宽容_DURATION = int(value)
            elif key == 'enable_recent_tolerance':
                ENABLE_RECENT宽容 = bool(int(value))
            elif key == 'recent_tolerance_duration':
                RECENT宽容_DURATION = int(value)
        
        logger.info(f"从数据库加载配置成功: DEBUG_MODE={DEBUG_MODE}, RADIUS_SECRET={RADIUS_SECRET}, MAX_FAILED_ATTEMPTS={MAX_FAILED_ATTEMPTS}, LOCKOUT_DURATION={LOCKOUT_DURATION}")
        logger.info(f"宽容认证配置: ENABLE_RECONNECT宽容={ENABLE_RECONNECT宽容}, RECONNECT宽容_DURATION={RECONNECT宽容_DURATION}, ENABLE_RECENT宽容={ENABLE_RECENT宽容}, RECENT宽容_DURATION={RECENT宽容_DURATION}")
    except Exception as e:
        logger.error(f"加载配置失败: {e}")

# 加载配置
load_config()

# 宽容认证检查
def check_tolerance_authentication(username, password, pkt):
    """检查宽容认证条件"""
    try:
        # 提取当前请求的信息
        current_time = datetime.datetime.now()
        protocol_type = None
        server_ip = None
        client_ip = None
        
        # 从请求包中提取信息
        if pkt:
            for attr_name, attr_values in pkt.items():
                for value in attr_values:
                    try:
                        attr_id = int(attr_name) if isinstance(attr_name, str) and attr_name.isdigit() else attr_name
                        if attr_id == 7:  # Framed-Protocol
                            if len(value) == 4:
                                protocol = struct.unpack('!I', value)[0]
                                protocol_name = FRAMED_PROTOCOLS.get(protocol, f'Unknown({protocol})')
                                protocol_type = protocol_name
                        elif attr_id == 67:  # Tunnel-Server-Endpoint
                            if isinstance(value, bytes):
                                server_ip = value.decode('utf-8', errors='ignore').lstrip(chr(value[0]))
                        elif attr_id == 66:  # Tunnel-Client-Endpoint
                            if isinstance(value, bytes):
                                client_ip = value.decode('utf-8', errors='ignore').lstrip(chr(value[0]))
                    except:
                        pass
            
            # 如果没有Tunnel-Client-Endpoint，则使用源IP作为客户端IP
            if not client_ip and hasattr(pkt, 'source') and pkt.source:
                client_ip = pkt.source[0]
            
            # 如果没有Tunnel-Server-Endpoint，则使用默认服务器IP
            if not server_ip:
                server_ip = '0.0.0.0'
        
        # 连接认证日志数据库
        conn = sqlite3.connect(AUTH_LOGS_DB_PATH)
        c = conn.cursor()
        
        # 检查12小时重连宽容认证
        if ENABLE_RECONNECT宽容:
            cutoff_time = current_time - datetime.timedelta(seconds=RECONNECT宽容_DURATION)
            c.execute('''
            SELECT password FROM auth_logs 
            WHERE username = ? 
            AND protocol_type = ? 
            AND server_ip = ? 
            AND client_ip = ? 
            AND result_code = 1000 
            AND timestamp >= ? 
            ORDER BY timestamp DESC 
            LIMIT 1
            ''', (username, protocol_type, server_ip, client_ip, cutoff_time.strftime('%Y-%m-%d %H:%M:%S')))
            
            result = c.fetchone()
            if result and result[0] == password:
                conn.close()
                return 'SUCCESS_RECONNECT'
        
        # 检查10分钟最近认证宽容
        if ENABLE_RECENT宽容:
            cutoff_time = current_time - datetime.timedelta(seconds=RECENT宽容_DURATION)
            c.execute('''
            SELECT password FROM auth_logs 
            WHERE username = ? 
            AND protocol_type = ? 
            AND server_ip = ? 
            AND result_code IN (1000, 1001, 1002) 
            AND timestamp >= ? 
            ORDER BY timestamp DESC 
            LIMIT 1
            ''', (username, protocol_type, server_ip, cutoff_time.strftime('%Y-%m-%d %H:%M:%S')))
            
            result = c.fetchone()
            if result and result[0] == password:
                conn.close()
                return 'SUCCESS_RECENT'
        
        conn.close()
        return None
    except Exception as e:
        logger.error(f"检查宽容认证失败: {e}")
        return None

# 记录认证日志
def log_auth_record(username, result, error_message=None, pkt=None, password=None):
    """记录认证日志到数据库"""
    try:
        # 认证结果代码定义
        RESULT_CODES = {
            'SUCCESS': 1000,  # 认证成功
            'SUCCESS_RECONNECT': 1001,  # 12小时重连宽容认证成功
            'SUCCESS_RECENT': 1002,  # 10分钟最近认证宽容成功
            'MISSING_USERNAME': 2001,  # 缺少用户名
            'MISSING_PASSWORD': 2002,  # 缺少密码
            'INVALID_USER': 2003,  # 用户无效或已禁用
            'INVALID_TOTP': 2004,  # TOTP验证失败
            'USER_LOCKED': 2005,  # 用户被锁定
            'AUTH_ERROR': 2006,  # 认证异常
            'SECRET_ERROR': 2007,  # 共享密钥错误
        }
        
        # 根据错误信息确定结果代码
        result_code = RESULT_CODES.get('SUCCESS', 9999)
        if result == 'FAILED':
            if 'Missing User-Name' in (error_message or ''):
                result_code = RESULT_CODES.get('MISSING_USERNAME')
            elif 'Missing User-Password' in (error_message or ''):
                result_code = RESULT_CODES.get('MISSING_PASSWORD')
            elif 'Invalid user or user disabled' in (error_message or ''):
                result_code = RESULT_CODES.get('INVALID_USER')
            elif 'Invalid TOTP code' in (error_message or ''):
                result_code = RESULT_CODES.get('INVALID_TOTP')
            elif 'User is temporarily locked out' in (error_message or ''):
                result_code = RESULT_CODES.get('USER_LOCKED')
            elif 'Cannot get shared secret' in (error_message or ''):
                result_code = RESULT_CODES.get('SECRET_ERROR')
            else:
                result_code = RESULT_CODES.get('AUTH_ERROR')
        elif result == 'SUCCESS_RECONNECT':
            result_code = RESULT_CODES.get('SUCCESS_RECONNECT')
        elif result == 'SUCCESS_RECENT':
            result_code = RESULT_CODES.get('SUCCESS_RECENT')
        
        # 提取请求包中的信息
        protocol_type = None
        nas_ip = None
        client_ip = None
        nas_port_id = None
        server_ip = None
        
        if pkt:
            # 从请求包中提取信息
            for attr_name, attr_values in pkt.items():
                for value in attr_values:
                    try:
                        attr_id = int(attr_name) if isinstance(attr_name, str) and attr_name.isdigit() else attr_name
                        if attr_id == 7:  # Framed-Protocol
                            if len(value) == 4:
                                protocol = struct.unpack('!I', value)[0]
                                protocol_name = FRAMED_PROTOCOLS.get(protocol, f'Unknown({protocol})')
                                protocol_type = protocol_name
                        elif attr_id == 4:  # NAS-IP-Address
                            if len(value) == 4:
                                nas_ip = '.'.join(str(b) for b in value)
                        elif attr_id == 66:  # Tunnel-Client-Endpoint
                            if isinstance(value, bytes):
                                client_ip = value.decode('utf-8', errors='ignore').lstrip(chr(value[0]))
                        elif attr_id == 67:  # Tunnel-Server-Endpoint
                            if isinstance(value, bytes):
                                server_ip = value.decode('utf-8', errors='ignore').lstrip(chr(value[0]))
                        elif attr_id == 87:  # NAS-Port-Id
                            if isinstance(value, bytes):
                                nas_port_id = value.decode('utf-8', errors='ignore')
                    except:
                        pass
            
            # 如果没有Tunnel-Client-Endpoint，则使用源IP作为客户端IP
            if not client_ip and hasattr(pkt, 'source') and pkt.source:
                client_ip = pkt.source[0]
            
            # 如果没有Tunnel-Server-Endpoint，则使用默认服务器IP
            if not server_ip:
                server_ip = '0.0.0.0'  # 假设服务器监听所有接口
        
        # 连接认证日志数据库
        conn = sqlite3.connect(AUTH_LOGS_DB_PATH)
        c = conn.cursor()
        
        # 插入日志记录
        c.execute('''
        INSERT INTO auth_logs (username, timestamp, protocol_type, nas_ip, server_ip, client_ip, nas_port_id, password, result, result_code, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            username,
            datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            protocol_type,
            nas_ip,
            server_ip,
            client_ip,
            nas_port_id,
            password,
            result,
            result_code,
            error_message
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f"认证日志记录成功: {username} - {result} (代码: {result_code})")
    except Exception as e:
        logger.error(f"记录认证日志失败: {e}")

# 黑名单相关函数
def is_user_blacklisted(username):
    """检查用户是否在黑名单中"""
    import time
    if username in blacklist:
        lockout_until = blacklist[username]
        if time.time() < lockout_until:
            return True
        else:
            # 锁定时间已过，从黑名单中移除
            del blacklist[username]
            logger.info(f"用户 {username} 已从黑名单中移除")
            return False
    return False

def add_to_blacklist(username):
    """添加用户到黑名单"""
    import time
    lockout_until = time.time() + LOCKOUT_DURATION
    blacklist[username] = lockout_until
    logger.warning(f"用户 {username} 已被添加到黑名单，锁定至 {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lockout_until))}")

def record_failed_attempt(username):
    """记录认证失败"""
    if username not in failed_attempts:
        failed_attempts[username] = 0
    failed_attempts[username] += 1
    
    logger.warning(f"用户 {username} 认证失败次数: {failed_attempts[username]}/{MAX_FAILED_ATTEMPTS}")
    
    # 检查是否达到最大失败次数
    if failed_attempts[username] >= MAX_FAILED_ATTEMPTS:
        add_to_blacklist(username)
        # 清除失败次数
        del failed_attempts[username]

def clear_failed_attempts(username):
    """清除失败次数"""
    if username in failed_attempts:
        del failed_attempts[username]
        logger.info(f"用户 {username} 认证成功，失败次数已清除")

# RADIUS属性名称映射表
RADIUS_ATTRIBUTES = {
    1: ('User-Name', '用户名'),
    2: ('User-Password', '密码'),
    3: ('CHAP-Password', 'CHAP密码'),
    4: ('NAS-IP-Address', 'NAS IP地址'),
    5: ('NAS-Port', 'NAS端口'),
    6: ('Service-Type', '服务类型'),
    7: ('Framed-Protocol', '协议类型'),
    8: ('Framed-IP-Address', '用户IP地址'),
    9: ('Framed-IP-Netmask', '子网掩码'),
    10: ('Framed-Routing', '路由'),
    11: ('Filter-Id', '过滤器ID'),
    12: ('Framed-MTU', 'MTU'),
    13: ('Framed-Compression', '压缩'),
    14: ('Login-IP-Host', '登录IP主机'),
    15: ('Login-Service', '登录服务'),
    16: ('Login-TCP-Port', '登录TCP端口'),
    18: ('Reply-Message', '回复消息'),
    19: ('Callback-Number', '回调号码'),
    20: ('Callback-Id', '回调ID'),
    22: ('Framed-Route', '路由'),
    23: ('Framed-IPX-Network', 'IPX网络'),
    24: ('State', '状态'),
    25: ('Class', '类'),
    26: ('Vendor-Specific', '厂商特定'),
    27: ('Session-Timeout', '会话超时'),
    28: ('Idle-Timeout', '空闲超时'),
    29: ('Termination-Action', '终止动作'),
    30: ('Called-Station-Id', '被叫站ID'),
    31: ('Calling-Station-Id', '主叫站ID'),
    32: ('NAS-Identifier', 'NAS标识符'),
    33: ('Proxy-State', '代理状态'),
    34: ('Login-LAT-Service', 'LAT服务'),
    35: ('Login-LAT-Node', 'LAT节点'),
    36: ('Login-LAT-Group', 'LAT组'),
    37: ('Framed-AppleTalk-Link', 'AppleTalk链路'),
    38: ('Framed-AppleTalk-Network', 'AppleTalk网络'),
    39: ('Framed-AppleTalk-Zone', 'AppleTalk区域'),
    40: ('Acct-Status-Type', '记账状态类型'),
    41: ('Acct-Delay-Time', '记账延迟时间'),
    42: ('Acct-Input-Octets', '输入字节数'),
    43: ('Acct-Output-Octets', '输出字节数'),
    44: ('Acct-Session-Id', '会话ID'),
    45: ('Acct-Authentic', '记账认证'),
    46: ('Acct-Session-Time', '会话时间'),
    47: ('Acct-Input-Packets', '输入包数'),
    48: ('Acct-Output-Packets', '输出包数'),
    49: ('Acct-Terminate-Cause', '终止原因'),
    50: ('Acct-Multi-Session-Id', '多会话ID'),
    51: ('Acct-Link-Count', '链路计数'),
    61: ('NAS-Port-Type', '端口类型'),
    62: ('Port-Limit', '端口限制'),
    63: ('Login-LAT-Port', 'LAT端口'),
    66: ('Tunnel-Client-Endpoint', '隧道客户端端点'),
    67: ('Tunnel-Server-Endpoint', '隧道服务端端点'),
    87: ('NAS-Port-Id', 'NAS端口ID'),
    88: ('Framed-Pool', '地址池'),
}

# 服务类型映射
SERVICE_TYPES = {
    1: 'Login',
    2: 'Framed-User',
    3: 'Callback Login',
    4: 'Callback Framed',
    5: 'Outbound',
    6: 'Administrative',
    7: 'NAS Prompt',
    8: 'Authenticate Only',
    9: 'Callback NAS Prompt',
    10: 'Call Check',
    11: 'Callback Administrative',
    12: 'Voice',
    13: 'Fax',
    14: 'Modem Relay',
    15: 'IAPP-Register',
    16: 'IAPP-AP-Check',
    17: 'Authorize Only',
    18: 'Framed-Management',
    19: 'Additional-Authorization',
}

# 端口类型映射
NAS_PORT_TYPES = {
    0: 'Async',
    1: 'Sync',
    2: 'ISDN Sync',
    3: 'ISDN Async V.120',
    4: 'ISDN Async V.110',
    5: 'Virtual',
    6: 'PIAFS',
    7: 'HDLC Clear Channel',
    8: 'X.25',
    9: 'X.75',
    10: 'G.3 Fax',
    11: 'SDSL - Symmetric DSL',
    12: 'ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase Modulation',
    13: 'ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone',
    14: 'IDSL - ISDN Digital Subscriber Line',
    15: 'Ethernet',
    16: 'xDSL - Digital Subscriber Line of unknown type',
    17: 'Cable',
    18: 'Wireless - Other',
    19: 'Wireless - IEEE 802.11',
    20: 'Token-Ring',
    21: 'FDDI',
    22: 'Wireless - CDMA2000',
    23: 'Wireless - UMTS',
    24: 'Wireless - 1X-EV',
    25: 'IAPP',
    26: 'FTTP - Fiber to the Premises',
    27: 'Wireless - IEEE 802.16',
    28: 'Wireless - IEEE 802.20',
    29: 'Wireless - IEEE 802.22',
    30: 'PPPoA - PPP over ATM',
    31: 'PPPoEoA - PPP over Ethernet over ATM',
    32: 'PPPoEoE - PPP over Ethernet over Ethernet',
    33: 'PPPoEoVLAN - PPP over Ethernet over VLAN',
    34: 'PPPoEoQinQ - PPP over Ethernet over IEEE 802.1QinQ',
    35: 'xPON - Passive Optical Network',
    36: 'Wireless - XGP',
    37: 'WiMAX',
}

# 协议类型映射
FRAMED_PROTOCOLS = {
    1: 'PPP',
    2: 'SLIP',
    3: 'AppleTalk Remote Access Protocol (ARAP)',
    4: 'Gandalf proprietary SingleLink/MultiLink',
    5: 'Xylogics proprietary IPX/SLIP',
    6: 'X.75 Synchronous',
    7: 'G.703 at 64Kbps',
    8: 'G.703 at 2Mbps',
    9: 'G.703 at 384Kbps',
    10: 'G.703 at 1.544Mbps',
    11: 'Frame Relay',
    12: 'EIA RS-232-D',
    13: 'EIA RS-449',
    14: 'EIA RS-530',
    15: 'EIA RS-422',
    16: 'EIA RS-423',
    17: 'Ethernet',
    18: 'X.25',
    19: 'HDLC',
    20: 'LAPB',
    21: 'V.120',
    22: 'V.110',
    23: 'CAPI',
    24: 'LAPF',
    25: 'ATM',
    26: 'Frame Relay over ATM',
    27: 'ISDN BRI',
    28: 'ISDN PRI',
    29: 'DSL',
    30: 'PPPoA',
    31: 'PPPoE',
    32: 'PPPoEoA',
    33: 'PPPoEoE',
    34: 'PPPoEoVLAN',
    35: 'PPPoEoQinQ',
    36: 'L2TP',
    37: 'PPTP',
    38: 'L2F',
    39: 'UDP',
    40: 'TCP',
    41: 'IPsec',
    42: 'MPLS',
    43: 'VLAN',
    44: 'QinQ',
}

def parse_attribute_value(attr_type, attr_value):
    """解析属性值"""
    try:
        if attr_type == 1:  # User-Name
            return f"用户名: {attr_value.decode('utf-8', errors='ignore')}"
        elif attr_type == 2:  # User-Password
            return "密码: (已加密)"
        elif attr_type == 3:  # CHAP-Password
            return "CHAP密码: (已加密)"
        elif attr_type == 4:  # NAS-IP-Address
            if len(attr_value) == 4:
                ip = '.'.join(str(b) for b in attr_value)
                return f"NAS IP地址: {ip}"
        elif attr_type == 5:  # NAS-Port
            if len(attr_value) == 4:
                port = struct.unpack('!I', attr_value)[0]
                return f"NAS端口: {port}"
        elif attr_type == 6:  # Service-Type
            if len(attr_value) == 4:
                service_type = struct.unpack('!I', attr_value)[0]
                service_name = SERVICE_TYPES.get(service_type, f'未知({service_type})')
                return f"服务类型: {service_name} ({service_type})"
        elif attr_type == 7:  # Framed-Protocol
            if len(attr_value) == 4:
                protocol = struct.unpack('!I', attr_value)[0]
                protocol_name = FRAMED_PROTOCOLS.get(protocol, f'未知({protocol})')
                return f"协议类型: {protocol_name} ({protocol})"
        elif attr_type == 8:  # Framed-IP-Address
            if len(attr_value) == 4:
                ip = '.'.join(str(b) for b in attr_value)
                return f"用户IP地址: {ip}"
        elif attr_type == 27:  # Session-Timeout
            if len(attr_value) == 4:
                timeout = struct.unpack('!I', attr_value)[0]
                return f"会话超时: {timeout}秒"
        elif attr_type == 32:  # NAS-Identifier
            return f"NAS标识符: {attr_value.decode('utf-8', errors='ignore')}"
        elif attr_type == 44:  # Acct-Session-Id
            return f"会话ID: {attr_value.decode('utf-8', errors='ignore')}"
        elif attr_type == 61:  # NAS-Port-Type
            if len(attr_value) == 4:
                port_type = struct.unpack('!I', attr_value)[0]
                port_type_name = NAS_PORT_TYPES.get(port_type, f'未知({port_type})')
                return f"端口类型: {port_type_name} ({port_type})"
        elif attr_type == 66:  # Tunnel-Client-Endpoint
            return f"隧道客户端IP: {attr_value.decode('utf-8', errors='ignore').lstrip(chr(attr_value[0]))}"
        elif attr_type == 67:  # Tunnel-Server-Endpoint
            return f"隧道服务端IP: {attr_value.decode('utf-8', errors='ignore').lstrip(chr(attr_value[0]))}"
        elif attr_type == 87:  # NAS-Port-Id
            return f"物理端口信息: {attr_value.decode('utf-8', errors='ignore')}"
        elif attr_type == 26:  # Vendor-Specific
            if len(attr_value) >= 4:
                vendor_id = struct.unpack('!I', attr_value[:4])[0]
                return f"厂商特定属性: 厂商ID={vendor_id}"
        
        # 默认返回原始值
        if isinstance(attr_value, bytes):
            if len(attr_value) == 4:
                num = struct.unpack('!I', attr_value)[0]
                return f"数值: {num}"
            return f"原始值: {attr_value.hex()}"
        return f"原始值: {attr_value}"
    except Exception as e:
        return f"解析失败: {str(e)}"

def log_attributes(pkt):
    """规范化输出请求包属性"""
    logger.info("请求包属性:")
    logger.info("| 属性类型 (ID) | 属性名称 | 原始值 (Hex/Bytes) | 解析后的含义/值 |")
    logger.info("| :--- | :--- | :--- | :--- |")
    
    for attr_name, attr_values in pkt.items():
        for value in attr_values:
            # 获取属性ID
            if isinstance(attr_name, tuple):
                # Vendor-Specific属性，格式为 (vendor_id, sub_attr_id)
                attr_id = f"{attr_name[0]}.{attr_name[1]}"
                attr_name_str = f"Vendor-Specific ({attr_name[0]}, {attr_name[1]})"
                raw_value = value if isinstance(value, bytes) else str(value).encode('utf-8')
                parsed_value = f"厂商ID: {attr_name[0]}, 子属性: {attr_name[1]}"
            else:
                # 标准属性 - attr_name已经是属性ID（数字字符串）
                # 尝试转换为整数
                try:
                    attr_id = int(attr_name) if isinstance(attr_name, str) and attr_name.isdigit() else attr_name
                except:
                    attr_id = attr_name
                
                attr_info = RADIUS_ATTRIBUTES.get(attr_id, (str(attr_name), str(attr_name)))
                attr_name_str = attr_info[0]
                raw_value = value if isinstance(value, bytes) else str(value).encode('utf-8')
                parsed_value = parse_attribute_value(attr_id, raw_value)
            
            # 格式化原始值
            if isinstance(raw_value, bytes):
                raw_value_str = f"`{raw_value}`"
            else:
                raw_value_str = f"`{raw_value}`"
            
            logger.info(f"| {attr_id} | {attr_name_str} | {raw_value_str} | {parsed_value} |")

class TOTPRadiusServer(server.Server):
    def __init__(self, addresses=['127.0.0.1'], dict_path='dictionary'):
        # 获取dictionary文件的绝对路径
        if not os.path.isabs(dict_path):
            dict_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), dict_path)
        
        # 以UTF-8编码打开dictionary文件
        with open(dict_path, 'r', encoding='utf-8') as f:
            dict_obj = Dictionary(f)
        server.Server.__init__(self, addresses=addresses, dict=dict_obj)
        
        # 添加hosts属性
        self.hosts = {}
        
        # 添加客户端（使用简单的方式）
        class ClientHost:
            def __init__(self, secret):
                self.secret = secret
        
        #self.hosts['127.0.0.1'] = ClientHost(b'secret')
        self.hosts['0.0.0.0'] = ClientHost(RADIUS_SECRET)
    
    def Run(self):
        """Main loop using select.select() for cross-platform compatibility."""
        import select
        import logging

        # Build list of file descriptors to monitor
        read_fds = []
        fd_to_type = {}

        for fd in self.authfds:
            read_fds.append(fd)
            fd_to_type[fd] = 'auth'
        for fd in self.acctfds:
            read_fds.append(fd)
            fd_to_type[fd] = 'acct'
        for fd in self.coafds:
            read_fds.append(fd)
            fd_to_type[fd] = 'coa'

        if not read_fds:
            raise RuntimeError("No sockets to listen on")

        logger = logging.getLogger('pyrad.server')
        logger.info("RADIUS server started. Listening on %d sockets.", len(read_fds))

        while True:
            try:
                ready, _, _ = select.select(read_fds, [], [], 1.0)
            except OSError as e:
                if e.errno == 4:  # EINTR
                    continue
                raise

            for fd in ready:
                pkt_type = fd_to_type.get(fd)
                if pkt_type == 'auth':
                    pkt = self._GrabPacket(lambda data, s=self: s.CreateAuthPacket(packet=data), fd)
                    if pkt:
                        try:
                            self._HandleAuthPacket(pkt)
                        except Exception:
                            logger.exception("Error handling auth packet")
                elif pkt_type == 'acct':
                    pkt = self._GrabPacket(lambda data, s=self: s.CreateAcctPacket(packet=data), fd)
                    if pkt:
                        try:
                            self._HandleAcctPacket(pkt)
                        except Exception:
                            logger.exception("Error handling acct packet")
                elif pkt_type == 'coa':
                    pkt = self._GrabPacket(lambda data, s=self: s.CreateCoAPacket(packet=data), fd)
                    if pkt:
                        try:
                            self._HandleCoaPacket(pkt)
                        except Exception:
                            logger.exception("Error handling CoA packet")

    def _HandleAuthPacket(self, pkt):  # 注意：带下划线！
        try:
            client_ip, client_port = pkt.source
            logger.info(f"收到认证请求来自 {client_ip}:{client_port}")
            

            
            # 检查是否为Status-Server请求（Code=12）
            if pkt.code == 12:
                logger.info(f"收到Status-Server请求")
                
                # 创建Status-Server响应
                reply = self.CreateReplyPacket(pkt)
                reply.code = 13  # Status-Server响应（Code=13）
                
                # 添加响应属性
                reply.AddAttribute('Reply-Message', 'Status-Server Response: Server is running')
                
                # 发送响应
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[OK] Status-Server响应已发送给 {client_ip}:{client_port}")
                return
            
            # 检查是否为Accounting-Request（Code=4）
            elif pkt.code == 4:
                logger.info(f"收到Accounting-Request请求")
                
                # 提取Accounting属性
                username = pkt.get('User-Name', ['未知'])[0]
                acct_session_id = pkt.get('Acct-Session-Id', ['未知'])[0]
                acct_status_type = pkt.get('Acct-Status-Type', ['未知'])[0]
                
                logger.info(f"用户: {username}")
                logger.info(f"会话ID: {acct_session_id}")
                logger.info(f"记账状态: {acct_status_type}")
                
                # 创建AccountingResponse响应
                reply = self.CreateReplyPacket(pkt)
                reply.code = 5  # Accounting-Response（Code=5）
                
                # 添加响应属性
                reply.AddAttribute('Reply-Message', 'Accounting-Response: Success')
                
                # 发送响应
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[OK] AccountingResponse响应已发送给 {client_ip}:{client_port}")
                return
            
            if 'User-Name' not in pkt:
                logger.warning("缺少 User-Name")
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccessReject
                reply.AddAttribute('Reply-Message', 'Missing User-Name attribute')
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[FAILED] Access-Reject响应已发送给 {client_ip}:{client_port} (缺少User-Name)")
                # 记录认证日志
                log_auth_record('Unknown', 'FAILED', 'Missing User-Name attribute', pkt, password=None)
                return
            
            username = pkt['User-Name'][0]
            logger.info(f"用户名: {username}")
            
            # 规范化输出请求包中的所有属性
            log_attributes(pkt)
            
            # 获取共享密钥
            if pkt.source[0] in self.hosts:
                secret = self.hosts[pkt.source[0]].secret
            elif '0.0.0.0' in self.hosts:
                secret = self.hosts['0.0.0.0'].secret
            else:
                logger.warning("无法获取共享密钥")
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccessReject
                reply.AddAttribute('Reply-Message', 'Cannot get shared secret')
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[FAILED] Access-Reject响应已发送给 {client_ip}:{client_port} (无法获取共享密钥)")
                # 记录认证日志
                log_auth_record(username, 'FAILED', 'Cannot get shared secret', pkt, password=None)
                return
            
            # 设置共享密钥到请求包对象
            pkt.secret = secret
            
            # 从原始数据包中解密User-Password
            totp_code = None
            vendor_id = None  # 存储请求包中的厂商ID
            try:
                # 尝试从原始数据包中解析User-Password属性
                logger.info(f"尝试从原始数据包中获取User-Password属性...")
                
                # 直接从原始数据包中解析User-Password属性
                raw_packet = pkt.raw_packet
                
                # 解析RADIUS数据包
                # RADIUS数据包格式: Code(1) + Identifier(1) + Length(2) + Authenticator(16) + Attributes(variable)
                code = raw_packet[0]
                identifier = raw_packet[1]
                length = struct.unpack('!H', raw_packet[2:4])[0]
                authenticator = raw_packet[4:20]
                attributes = raw_packet[20:]
                
                # 解析属性
                pos = 0
                while pos < len(attributes):
                    attr_type = attributes[pos]
                    attr_len = attributes[pos + 1]
                    attr_value = attributes[pos + 2:pos + attr_len]
                    
                    # User-Password属性类型为2
                    if attr_type == 2:
                        logger.info(f"找到User-Password属性 (hex): {attr_value.hex()}")
                        
                        # 使用RADIUS协议的密码解密算法
                        # 解密算法: Cn = Pn XOR MD5(Secret + Cn-1)
                        # 其中C0 = Request Authenticator
                        password = b''
                        last = authenticator
                        
                        # 分块解密，每块16字节
                        for i in range(0, len(attr_value), 16):
                            block = attr_value[i:i+16]
                            hash = hashlib.md5(secret + last).digest()
                            decrypted_block = bytes([block[j] ^ hash[j] for j in range(len(block))])
                            password += decrypted_block
                            last = block
                        
                        # 移除填充的空字节
                        password = password.rstrip(b'\x00')
                        
                        # 转换为字符串
                        totp_code = password.decode('utf-8', errors='ignore')
                        
                        # 调试模式：PAP认证总是通过
                        if DEBUG_MODE:
                            logger.info("🔧 调试模式：PAP认证总是通过")
                        # 不再使用break，继续解析其他属性
                        # break
                    
                    # CHAP-Password属性类型为3
                    elif attr_type == 3:
                        # CHAP-Password格式: CHAP标识符(1字节) + CHAP响应(16字节)
                        chap_id = attr_value[0]
                        chap_response = attr_value[1:17]
                        
                        # CHAP验证: response = MD5(CHAP标识符 + 密码 + challenge)
                        # 在RADIUS中，challenge通常就是Request Authenticator
                        
                        # 查询数据库获取用户的TOTP密钥
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute('SELECT totp_secret, enabled FROM users WHERE username = ?', (username,))
                        user = c.fetchone()
                        conn.close()
                        
                        if not user or not user[1]:
                            logger.warning(f"用户 {username} 无效")
                            reply = self.CreateReplyPacket(pkt)
                            reply.code = packet.AccessReject
                            self.SendReplyPacket(pkt.fd, reply)
                            return
                        
                        totp_secret = user[0]
                        
                        # 尝试多个TOTP验证码（当前时间窗口）
                        import time
                        current_time = int(time.time())
                        totp = pyotp.TOTP(totp_secret)
                        
                        # 调试模式：CHAP认证总是通过
                        if DEBUG_MODE:
                            logger.info("🔧 调试模式：CHAP认证总是通过")
                            totp_code = totp.now()
                            # 不再使用break，继续解析其他属性
                            # break
                        
                        # 尝试当前时间窗口和前后各1个时间窗口
                        for offset in range(-1, 2):
                            test_code = totp.at(current_time + offset * 30)
                            
                            # 计算CHAP响应
                            expected_response = hashlib.md5(
                                bytes([chap_id]) + 
                                test_code.encode('utf-8') + 
                                authenticator
                            ).digest()
                            
                            # 比较CHAP响应
                            if chap_response == expected_response:
                                totp_code = test_code
                                # 不再使用break，继续解析其他属性
                                # break
                        
                        if totp_code:
                            # 不再使用break，继续解析其他属性
                            pass
                    
                    # Vendor-Specific属性类型为26
                    elif attr_type == 26:
                        # Vendor-Specific格式: Vendor-ID(4字节) + 厂商特定数据
                        if len(attr_value) >= 4:
                            vendor_id = struct.unpack('!I', attr_value[:4])[0]
                    
                    pos += attr_len
                
                if not totp_code:
                    logger.warning("无法找到User-Password属性")
                    
            except Exception as e:
                logger.error(f"解密User-Password失败: {e}")
                logger.exception("详细错误:")
            
            if not totp_code:
                logger.warning("缺少 User-Password")
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccessReject
                self.SendReplyPacket(pkt.fd, reply)
                # 记录认证日志
                log_auth_record(username, 'FAILED', 'Missing User-Password', pkt, password=None)
                return

            # 确保totp_code是字符串
            if isinstance(totp_code, bytes):
                totp_code = totp_code.decode('utf-8')
                logger.info(f"转换后的值: {totp_code}")

            # 检查用户是否在黑名单中
            if is_user_blacklisted(username):
                logger.warning(f"用户 {username} 在黑名单中，拒绝认证")
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccessReject
                reply.AddAttribute('Reply-Message', 'User is temporarily locked out')
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[FAILED] Access-Reject响应已发送给 {client_ip}:{client_port} (用户在黑名单中)")
                # 记录认证日志
                log_auth_record(username, 'FAILED', 'User is temporarily locked out', pkt, password=totp_code)
                return

            # 查询数据库
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('SELECT totp_secret, enabled FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            conn.close()

            if not user or not user[1]:
                logger.warning(f"用户 {username} 无效")
                # 记录失败尝试
                record_failed_attempt(username)
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccessReject
                reply.AddAttribute('Reply-Message', 'Invalid user or user disabled')
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[FAILED] Access-Reject响应已发送给 {client_ip}:{client_port} (用户无效)")
                # 记录认证日志
                log_auth_record(username, 'FAILED', 'Invalid user or user disabled', pkt, password=totp_code)
                return

            # 验证 TOTP
            totp = pyotp.TOTP(user[0])
            #调试让密码总是正确
            if DEBUG_MODE or totp.verify(totp_code, valid_window=1):
                # 认证成功，清除失败次数
                clear_failed_attempts(username)
                logger.info(f"[OK] {username} 认证成功")
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccessAccept
                # 添加Session-Timeout属性
                reply.AddAttribute('Session-Timeout', 9999999)
                
                # 使用从请求包中提取的厂商ID
                if vendor_id:
                    logger.info(f"使用请求包中的厂商ID: {vendor_id}")
                else:
                    vendor_id = 2011  # 默认使用HUAWEI厂商ID
                    logger.info(f"未从请求包中提取到厂商ID，使用默认值: {vendor_id}")
                
                # 添加第一个Vendor-Specific属性
                value1 = b'h323-credit-amount=99999.99'
                data_length1 = len(value1)
                inner_length1 = 2 + data_length1  # 2字节VSA Header + 数据长度
                
                vendor_data1 = struct.pack('!I', vendor_id)  # 使用提取的厂商ID
                vendor_data1 += struct.pack('!B', 101)   # 子属性类型 (Huawei-LI-ID)
                vendor_data1 += struct.pack('!B', inner_length1)    # 子属性长度
                vendor_data1 += value1  # 子属性值
                reply.AddAttribute('Vendor-Specific', vendor_data1)
                
                # 添加第二个Vendor-Specific属性
                value2 = b'h323-return-code=0'
                data_length2 = len(value2)
                inner_length2 = 2 + data_length2  # 2字节VSA Header + 数据长度
                
                vendor_data2 = struct.pack('!I', vendor_id)  # 使用提取的厂商ID
                vendor_data2 += struct.pack('!B', 103)   # 子属性类型 (Huawei-LI-Md-Port)
                vendor_data2 += struct.pack('!B', inner_length2)    # 子属性长度
                vendor_data2 += value2  # 子属性值
                reply.AddAttribute('Vendor-Specific', vendor_data2)
                
                # 发送响应
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[OK] Access-Accept响应已发送给 {client_ip}:{client_port}")
                # 记录认证日志
                log_auth_record(username, 'SUCCESS', None, pkt, password=totp_code)
            else:
                # 检查宽容认证
                tolerance_result = check_tolerance_authentication(username, totp_code, pkt)
                if tolerance_result:
                    # 宽容认证成功
                    clear_failed_attempts(username)
                    logger.info(f"[OK] {username} 宽容认证成功 ({tolerance_result})")
                    reply = self.CreateReplyPacket(pkt)
                    reply.code = packet.AccessAccept
                    # 添加Session-Timeout属性
                    reply.AddAttribute('Session-Timeout', 9999999)
                    
                    # 使用从请求包中提取的厂商ID
                    if vendor_id:
                        logger.info(f"使用请求包中的厂商ID: {vendor_id}")
                    else:
                        vendor_id = 2011  # 默认使用HUAWEI厂商ID
                        logger.info(f"未从请求包中提取到厂商ID，使用默认值: {vendor_id}")
                    
                    # 添加第一个Vendor-Specific属性
                    value1 = b'h323-credit-amount=99999.99'
                    data_length1 = len(value1)
                    inner_length1 = 2 + data_length1  # 2字节VSA Header + 数据长度
                    
                    vendor_data1 = struct.pack('!I', vendor_id)  # 使用提取的厂商ID
                    vendor_data1 += struct.pack('!B', 101)   # 子属性类型 (Huawei-LI-ID)
                    vendor_data1 += struct.pack('!B', inner_length1)    # 子属性长度
                    vendor_data1 += value1  # 子属性值
                    reply.AddAttribute('Vendor-Specific', vendor_data1)
                    
                    # 添加第二个Vendor-Specific属性
                    value2 = b'h323-return-code=0'
                    data_length2 = len(value2)
                    inner_length2 = 2 + data_length2  # 2字节VSA Header + 数据长度
                    
                    vendor_data2 = struct.pack('!I', vendor_id)  # 使用提取的厂商ID
                    vendor_data2 += struct.pack('!B', 103)   # 子属性类型 (Huawei-LI-Md-Port)
                    vendor_data2 += struct.pack('!B', inner_length2)    # 子属性长度
                    vendor_data2 += value2  # 子属性值
                    reply.AddAttribute('Vendor-Specific', vendor_data2)
                    
                    # 发送响应
                    self.SendReplyPacket(pkt.fd, reply)
                    logger.info(f"[OK] Access-Accept响应已发送给 {client_ip}:{client_port}")
                    # 记录认证日志
                    log_auth_record(username, tolerance_result, None, pkt, password=totp_code)
                else:
                    # 认证失败，记录失败尝试
                    record_failed_attempt(username)
                    logger.warning(f"[FAILED] {username} TOTP 验证失败")
                    reply = self.CreateReplyPacket(pkt)
                    reply.code = packet.AccessReject
                    reply.AddAttribute('Reply-Message', 'Invalid TOTP code')
                    
                    # 发送响应
                    self.SendReplyPacket(pkt.fd, reply)
                    logger.info(f"[FAILED] Access-Reject响应已发送给 {client_ip}:{client_port}")
                    # 记录认证日志
                    log_auth_record(username, 'FAILED', 'Invalid TOTP code', pkt, password=totp_code)

        except Exception as e:
            logger.exception("认证异常")
            reply = self.CreateReplyPacket(pkt)
            reply.code = packet.AccessReject
            reply.AddAttribute('Reply-Message', 'Authentication error')
            self.SendReplyPacket(pkt.fd, reply)
            logger.info(f"[FAILED] Access-Reject响应已发送给 {client_ip}:{client_port} (认证异常)")
            # 记录认证日志
            log_auth_record(username, 'FAILED', f'Authentication error: {str(e)}', pkt, password=totp_code)

    def HandleAcctPacket(self, pkt):  # 注意：不带下划线！
        try:
            client_ip, client_port = pkt.source
            logger.info(f"收到记账请求来自 {client_ip}:{client_port}")
            

            
            # 检查是否为AccountingRequest
            if pkt.code == packet.AccountingRequest:
                logger.info(f"收到AccountingRequest请求")
                
                # 提取Accounting属性
                username = pkt.get('User-Name', ['未知'])[0]
                acct_session_id = pkt.get('Acct-Session-Id', ['未知'])[0]
                acct_status_type = pkt.get('Acct-Status-Type', ['未知'])[0]
                
                logger.info(f"用户: {username}")
                logger.info(f"会话ID: {acct_session_id}")
                logger.info(f"记账状态: {acct_status_type}")
                
                # 创建AccountingResponse响应
                reply = self.CreateReplyPacket(pkt)
                reply.code = packet.AccountingResponse
                
                # 添加响应属性
                reply.AddAttribute('Reply-Message', 'Accounting-Response: Success')
                
                # 发送响应
                self.SendReplyPacket(pkt.fd, reply)
                logger.info(f"[OK] AccountingResponse响应已发送给 {client_ip}:{client_port}")
                
            else:
                logger.info(f"收到AccountingResponse响应")
                
        except Exception as e:
            logger.error(f"处理记账请求失败: {e}")
            logger.exception("详细错误:")

if __name__ == '__main__':
    print("Radius服务器启动中...")
    print("监听端口: 1812")
    
    try:
        srv = TOTPRadiusServer(addresses=['0.0.0.0'])
        srv.Run()
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        logger.exception("服务器启动失败")
        print(f"错误: {e}")