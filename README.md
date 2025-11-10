# HTTP ENDPOINT Adapter For AstrBot

为 [AstrBot](https://github.com/Soulter/AstrBot) 设计的 HTTP ENDPOINT 适配器插件，通过 HTTP API 实现与外部系统的双向消息集成。

---

## 功能特性

- 通过 HTTP API 接收和发送消息
- 支持文本和图片消息类型
- 自动注册 API 端点
- JWT Token 认证保护
- 响应缓存机制：缓存astrbot发送的消息
  - http与im消息平台最大区别在于，im是双向通讯，astrbot每次处理im消息都支持多次发消息到im，以及发送主动消息给im，短连接的http下客户端只能通过轮训才能确保获得全部消息
  - 如果使用http长连接或者websocket，就不是HTTP API了
- 响应数据包含[item_id](file://d:\develop\python\astrbot_plugin_http_adapter\http_endpoint_adapter.py#L285-L285)字段，支持去重

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
    api_key: ""                     # API 认证密钥（自动生成），只读不可修改，需要更新请 清空或修改seek
    seek: ""                        # 用于生成api_key（自动生成），清空会自动生成并重置api_key
    cache_size: "4096"              # 响应缓存大小，通过msg_id标记每个请求，并通过msg_id缓存响应数据
    cache_ttl: "10"                 # 缓存有效时间（秒）
```

## 使用说明

### API 调用地址

- 外部系统调用地址：`http://your-host:port/api/plug/[api_endpoint]`
- 例如：如果 [api_endpoint](file://d:\develop\python\astrbot_plugin_http_adapter\http_endpoint_adapter.py#L135-L135) 配置为 `/v1/chat`，则完整地址为 `http://your-host:port/api/plug/v1/chat`
- 所有请求需在 Header 中添加认证信息：`Authorization: Bearer [api_key]`

### 接收消息格式

向配置的 API 端点发送 POST 请求：

```json
{
  "msg_id": "abcd1234",
  "query": "你好",
  "type": "text",
  "sender_id": "user123",
  "sender_nickname": "用户昵称"
}
```
> msg_id: 标记每个请求
> sender_id: 用户id、会话id

图片消息：
```json
{
  "msg_id": "abcd1234",
  "type": "image",
  "url": "https://example.com/image.jpg",
  "sender_id": "user123",
  "sender_nickname": "用户昵称"
}
```

### 响应消息格式

AstrBot 处理后会返回响应，每个数据项包含[item_id](file://d:\develop\python\astrbot_plugin_http_adapter\http_endpoint_adapter.py#L285-L285)字段，可用于去重：

```json
{
  "data": [
    {
      "type": "text",
      "content": "你好！有什么可以帮助你的吗？",
      "item_id": "1nA8KzIyiY"
    }
  ],
  "msg_id": "abcd1234"
}
```
> msg_id: 标记每个请求，与请求时保持一致
> data: astrbot 可能多次发送的消息
> item_id: astrbot每次发送消息的id，不会变

## 技术架构

- 使用 `register_web_api` 方法注册 HTTP 端点
- 通过 Future 机制匹配请求与响应
- 使用 TTLCache 实现响应数据缓存

## 依赖要求

- AstrBot >= 4.5.1
- Python >= 3.11

## 许可证

本项目采用 MIT 许可证，详情请见 [LICENSE](LICENSE) 文件。