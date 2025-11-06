# HTTP ENDPOINT Adapter For AstrBot

为 [AstrBot](https://github.com/Soulter/AstrBot) 设计的 HTTP ENDPOINT 适配器插件，通过 HTTP API 实现与外部系统的双向消息集成。

通过该插件，您可以将 AstrBot 的能力集成到任何支持 HTTP 请求的系统中，实现自定义的消息收发功能。

---

## 功能特性

- **双向通信**: 通过 HTTP API 接收外部消息并发送回复
- **消息匹配**: 使用唯一 ID 匹配请求与响应，确保上下文一致性
- **多格式支持**: 支持文本和图片消息类型
- **API 管理**: 自动注册和管理 API 端点
- **安全认证**: 支持 JWT Token 认证（可选）
- **灵活配置**: 支持自定义 API 端点和认证密钥

## 安装方式

### 方法一：通过插件管理器安装（推荐）

1. 在 AstrBot 管理界面中进入插件管理
2. 选择"安装插件"，上传本插件的 ZIP 包

### 方法二：手动安装

1. 克隆或下载本仓库到 AstrBot 的 plugins 目录
2. 在 AstrBot 配置文件中启用插件

## 配置说明

在 AstrBot 的配置文件中添加以下配置项：

```yaml
platform:
  - id: "http_endpoint"
    type: "http_endpoint"
    enable: true
    api_endpoint: "/v1/chat"        # API 端点路径
    api_key: ""                     # API 认证密钥（自动生成）
```

## 使用说明

### 接收消息格式

向配置的 API 端点发送 POST 请求，消息格式如下：

```json
{
  "query": "你好",
  "type": "text",
  "sender_id": "user123",
  "sender_nickname": "用户昵称"
}
```

图片消息格式：
```json
{
  "type": "image",
  "url": "https://example.com/image.jpg",
  "sender_id": "user123",
  "sender_nickname": "用户昵称"
}
```

### 响应消息格式

AstrBot 处理后会返回响应消息：

```json
{
  "data": [
    {
      "type": "text",
      "content": "你好！有什么可以帮助你的吗？"
    }
  ],
  "request_id": "abcd1234"
}
```

图片消息响应：
```json
{
  "data": [
    {
      "type": "image",
      "content": "https://example.com/response_image.jpg"
    }
  ],
  "request_id": "abcd1234"
}
```

## 技术架构

- **消息接收**: 通过 `register_web_api` 方法注册 HTTP 端点接收外部消息
- **消息处理**: 使用 Future 机制匹配请求与响应
- **消息转换**: 将 HTTP 消息转换为 AstrBot 内部消息格式
- **事件处理**: 通过 [HttpEndpointPlatformEvent](./http_endpoint_event.py) 处理消息事件

## 依赖要求

- AstrBot >= 4.5.1
- Python >= 3.11

## 开发与贡献

欢迎提交 Issue 和 Pull Request 来改进这个插件。

### 本地开发

```bash
# 克隆项目
git clone https://github.com/fluidcat/astrbot_plugin_http_adapter.git

# 安装依赖
pip install -e .
# 或使用 uv
uv sync
```

## 许可证

本项目采用 MIT 许可证，详情请见 [LICENSE](LICENSE) 文件。

## 声明

本插件仅供学习和研究目的。