# HTTP ENDPOINT Adapter For AstrBot

为 [AstrBot](https://github.com/Soulter/AstrBot) 设计的 HTTP ENDPOINT 适配器插件，通过 HTTP API 实现与外部系统的双向消息集成。

## 使用说明

### 配置参数

在 AstrBot 的配置文件中添加以下配置项：

```yaml
platform:
  - id: "http_endpoint"
    type: "http_endpoint"
    enable: true
    hep_api_endpoint: "/v1/chat"        # API 端点路径
    hep_api_key: ""                     # API 认证密钥（自动生成）
    hep_api_key_ttl: "604800"           # API密钥有效期，默认7天(604800秒)
    hep_callback_switch: false          # 消息回调开关，开启后响应缓存则失效
    hep_callback_url: ""                # 消息回调URL，消息回调开关开启时必填
    hep_cache_size: "4096"              # 响应缓存大小
    hep_cache_ttl: "300"                # 缓存有效时间（秒），默认300秒
```

### API 调用地址

- 外部系统调用地址：`http://your-host:port/api/plug/[api_endpoint]`
- 例如：如果 api_endpoint 配置为 `/v1/chat`，则完整地址为 `http://your-host:port/api/plug/v1/chat`
- 所有请求需在 Header 中添加认证信息：`Authorization: Bearer [api_key]`

### 刷新API密钥

在API密钥过期前，可以通过以下端点刷新：

- 需要在过期前使用即将过期的秘钥刷新
- 刷新密钥地址：`http://your-host:port/api/plug/hep/refresh_token`
- 请求方法：POST 或 GET
- 成功后将返回新的API密钥

### 消息通信模式

#### HTTP轮询模式（默认）

当 `hep_callback_switch` 设置为 `false` 时，使用HTTP轮询模式：

- 客户端向API端点发送消息请求
- AstrBot处理消息并缓存响应数据
- 客户端通过轮询获取完整响应数据
- 返回数据包含指定 `msg_id` 对应的全量响应以及AstrBot主动发送的消息

#### HTTP回调模式

当 `hep_callback_switch` 设置为 `true` 时，使用HTTP回调模式：

- AstrBot发送的每个消息都会推送到配置的 `hep_callback_url`, post方法发送json
- 回调采用POST请求，数据格式与轮询模式下的响应格式一致
- 回调失败时会重试，最多重试3次，超时时间为10秒
- 启用回调模式后，响应缓存机制将失效

推送数据样例：
```json
{
  "msg_id": "1233",
  "data": [
    {
      "item_id": "4zchNMkO08",
      "type": "text",
      "content": "你好！有什么可以帮助你的吗？"
    }
  ]
}
```

### 发送消息到AstrBot

向配置的 API 端点发送 POST 请求：

文本消息：
```json
{
  "msg_id": "abcd1234",
  "query": "你好",
  "type": "text",
  "sender_id": "user123",
  "sender_nickname": "用户昵称"
}
```

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

### 接收AstrBot的响应

AstrBot 处理后会返回响应，每个数据项包含 item_id 字段，可用于去重：

```json
{
  "data": [
    {
      "type": "text",
      "content": "你好！有什么可以帮助你的吗？",
      "item_id": "1nA8KzIyiY"
    }
  ],
  "detail": "success",
  "code": 0,
  "api_key_ttl": 603981,
  "msg_id": "abcd1234"
}
```

> msg_id: 标记每个请求，与请求时保持一致
> api_key_ttl: 当前请求使用的api_key剩余有效时间，单位：秒
> detail：请求处理附加信息
> data: AstrBot 可能多次发送的消息
> item_id: AstrBot每次发送消息的唯一标识，可用于客户端去重处理

### API密钥安全说明

- API密钥首次使用时从消息平台配置中获取
- API密钥具有有效期，需在过期前通过 `/hep/refresh_token` 端点刷新
- 如果密钥过期，只能从消息平台配置中重新获取
- 特别注意：API密钥是AstrBot通用token，拥有与通过Web登录AstrBot相同的权限
- 如果API密钥泄露，将存在AstrBot安全风险，请妥善保管

## 依赖要求

- AstrBot >= 4.5.1
- Python >= 3.11

## 许可证

本项目采用 MIT 许可证，详情请见 [LICENSE](LICENSE) 文件。