import pyotp
import time

totp_secret = '25GFN7KHPXMXVBFZ'
totp = pyotp.TOTP(totp_secret)

current_time = int(time.time())
print(f"当前时间戳: {current_time}")
print(f"当前TOTP验证码: {totp.now()}")

# 显示前后时间窗口的验证码
for offset in range(-2, 3):
    test_code = totp.at(current_time + offset * 30)
    print(f"offset={offset}: {test_code}")
