# TOTP Radius认证服务

## 项目结构

```
TOTPRadius/
├── backend/           # 后端服务
│   ├── radius_server.py  # RADIUS服务器
│   └── dictionary      # RADIUS字典文件
├── frontend/          # 前端界面和API服务
│   ├── app.py        # Flask应用（提供前端界面和API）
│   └── index.html    # 主页面
├── db/               # 数据库目录
│   └── totp_radius.db   # SQLite数据库
└── README.md         # 项目说明
```

## 启动服务

### 1. 启动RADIUS服务器

```bash
cd backend
python radius_server.py
```

RADIUS服务器将在端口 `1812`（认证）和 `1813`（记账）上运行。

### 2. 启动前端和API服务

```bash
cd frontend
python app.py
```

前端界面和API服务将在 `http://localhost:8080` 上运行。

## 使用说明

### 访问前端界面

在浏览器中打开 `http://localhost:8080`，系统会提示输入HTTP认证信息：
- 用户名：`admin`
- 密码：`admin123`

### 用户认证

1. 在"用户认证"标签页中，输入用户名和TOTP验证码
2. 点击"认证"按钮进行验证

### 用户管理

1. 在"用户管理"标签页中，您可以：
   - 添加新用户（自动生成TOTP密钥）
   - 启用/禁用用户
   - 删除用户

2. 添加用户后，会显示一个二维码，可以使用Google Authenticator等认证器扫描添加

### 配置管理

在"配置管理"标签页中，您可以：
- 启用/禁用调试模式（调试模式下，任何密码验证都通过）
- 修改RADIUS共享密钥
- 保存配置后，需要重启RADIUS服务器使配置生效

## API接口

### 获取用户列表

```
GET /api/users
```

### 添加用户

```
POST /api/users
Content-Type: application/json

{
  "username": "testuser"
}
```

### 更新用户

```
PUT /api/users/{user_id}
Content-Type: application/json

{
  "enabled": true
}
```

### 删除用户

```
DELETE /api/users/{user_id}
```

### 验证TOTP

```
POST /api/verify
Content-Type: application/json

{
  "username": "testuser",
  "totp_code": "123456"
}
```

### 获取配置

```
GET /api/config
```

### 更新配置

```
POST /api/config
Content-Type: application/json

{
  "debug_mode": "1",
  "radius_secret": "secotp"
}
```

## RADIUS服务器功能

- 支持PAP认证（User-Password）
- 支持CHAP认证（CHAP-Password）
- 支持Status-Server请求
- 支持Accounting功能
- 从数据库中读取配置（调试模式和共享密钥）
- 根据请求包中的厂商ID动态构造回复包中的Vendor-Specific属性
- 详细的日志记录

## 注意事项

- 前端和API服务现在运行在同一个服务器上（端口8080）
- 数据库已移到项目根目录的 `db` 文件夹
- 前端界面会自动连接到同一服务器的API接口
- 管理功能受到HTTP认证保护
- 保存配置后，需要重启RADIUS服务器使配置生效
