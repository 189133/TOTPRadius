import pyotp

totp = pyotp.TOTP('25GFN7KHPXMXVBFZ')
print(f'TOTP验证码: {totp.now()}')