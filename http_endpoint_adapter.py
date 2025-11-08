import asyncio
import secrets
import string
from typing import Optional

import jwt
from jwt.exceptions import (
    InvalidTokenError,
    DecodeError,
    ExpiredSignatureError,
    InvalidSignatureError
)

from astrbot.api import logger
from astrbot.api.message_components import Image, Plain
from astrbot.api.platform import (
    AstrBotMessage,
    MessageMember,
    Platform,
    PlatformMetadata,
    register_platform_adapter,
    MessageType,
)
from astrbot.core import astrbot_config

from . import api_plugin_context
from .http_endpoint_event import HttpEndpointPlatformEvent


def _inject_astrbot_field_metadata():
    try:
        from astrbot.core.config.default import CONFIG_METADATA_2

        pg = CONFIG_METADATA_2.get("platform_group")
        if not isinstance(pg, dict):
            return
        metadata = pg.get("metadata")
        if not isinstance(metadata, dict):
            return
        platform = metadata.get("platform")
        if not isinstance(platform, dict):
            return
        items = platform.get("items")
        if not isinstance(items, dict):
            return

        adapter_config = {
            # 核心配置
            "api_endpoint": {
                "description": "API端点URL",
                "type": "string",
                "hint": "必填项。HTTP ENDPOINT的基地址。",
                "obvious_hint": True,
            },
            "api_key": {
                "description": "API密钥",
                "type": "string",
                "hint": "用于API认证的密钥，自动生成，清空会自动生成新的",
            },
            "seek": {
                "description": "seek",
                "type": "string",
                "hint": "seek，自动生成，清空会自动生成新的",
            },
        }

        # 仅在缺失时新增；若已存在则尽量补齐缺失的字段
        for k, v in adapter_config.items():
            if k not in items:
                items[k] = v
            else:
                it = items[k]
                if "description" not in it and "description" in v:
                    it["description"] = v["description"]
                if "type" not in it and "type" in v:
                    it["type"] = v["type"]
                if "hint" not in it and "hint" in v:
                    it["hint"] = v["hint"]
                if "obvious_hint" not in it and "obvious_hint" in v:
                    it["obvious_hint"] = v["obvious_hint"]

        logger.debug("已为 HTTP ENDPOINT 适配器注入字段元数据")
    except Exception as e:
        try:
            logger.debug(f"注入 HTTP ENDPOINT 字段元数据失败: {e}")
        except Exception:
            pass


@register_platform_adapter(
    "http_endpoint",
    "HTTP ENDPOINT Adapter",
    default_config_tmpl={
        "id": "http_endpoint",
        "type": "http_endpoint",
        "enable": False,
        "hint": "HTTP ENDPOINT适配器：通过HTTP API接收和发送消息。",
        "api_endpoint": "/v1/chat",
        "api_key": "",
        "seek": "",
    },
    adapter_display_name="HTTP ENDPOINT",
)
class HttpEndpointAdapter(Platform):
    """HTTP ENDPOINT Adapter"""

    def __init__(
            self,
            platform_config: dict,
            platform_settings: dict,
            event_queue: asyncio.Queue
    ):
        super().__init__(event_queue)
        self.platform_config = platform_config
        self.platform_settings = platform_settings
        logger.info("HTTP ENDPOINT Adapter 正在初始化...")
        # 配置验证
        self._validate_config(platform_config)

        logger.info("HTTP ENDPOINT Adapter 配置验证通过。")
        self.config = platform_config
        self.settings = platform_settings
        self.api_endpoint = platform_config.get("api_endpoint")
        self.api_key = platform_config.get("api_key")
        self.seek = platform_config.get("seek")

        # 存储待处理的HTTP请求
        self._pending_requests = {}

        self._running = False
        self.future = asyncio.Future()
        logger.info("HTTP ENDPOINT Adapter 初始化完成。")

    def api_terminate(self):
        apis = api_plugin_context.plugin_context.registered_web_apis
        for idx, item in enumerate(apis):
            if item[0] == self.api_endpoint:
                apis.pop(idx)
                break

    def api_register(self):
        if not self.seek:
            self.api_key = None
            self.seek = self.generate_id(length=16)
            self.platform_config.update({"seek": self.seek})
            astrbot_config.save_config()
        if not self.api_key:
            self.api_key = self.generate_jwt()
            self.platform_config.update({"api_key": self.api_key})
            astrbot_config.save_config()
        if (hasattr(api_plugin_context, 'plugin_context') and
                api_plugin_context.plugin_context and
                hasattr(api_plugin_context.plugin_context, 'register_web_api')):
            api_plugin_context.plugin_context.register_web_api(
                route=self.api_endpoint,
                view_handler=self.receive_http_request,
                methods=["POST"],
                desc="HTTP ENDPOINT 接收消息"
            )

    async def receive_http_request(self):
        from quart import request, jsonify
        # 检查token是否有效
        try:
            auth_header = request.headers.get("Authorization")
            self.token_check(auth_header)
        except ValueError as e:
            return jsonify({"error": str(e)}), 401
        except Exception as e:
            return jsonify({"error": "Invalid Authorization"}), 401

        try:
            # 获取请求数据
            request_data = await request.get_json()

            # 验证请求数据
            if not request_data:
                return jsonify({"error": "Invalid JSON data"}), 400

            message = self.convert_message(request_data)
            # 请求ID
            msg_id = message.message_id
            if self._pending_requests.get('msg_id'):
                return jsonify({"error": f"message：{msg_id} 正在处理中"}), 409

            # 创建Future对象用于存储响应
            response_future = asyncio.Future()

            # 将请求ID和Future存储在适配器中
            self._pending_requests[msg_id] = response_future

            if message:
                # 直接处理消息
                await self.handle_msg(message)

            # 等待响应
            try:
                # 设置超时时间，避免无限等待
                response_data = await asyncio.wait_for(response_future, timeout=30.0)

                # 清理Future
                if msg_id in self._pending_requests:
                    del self._pending_requests[msg_id]

                # 返回响应数据
                if isinstance(response_data, dict):
                    return jsonify(response_data), 200
                else:
                    return str(response_data), 200
            except asyncio.TimeoutError:
                # 清理超时的Future
                if msg_id in self._pending_requests:
                    del self._pending_requests[msg_id]
                return jsonify({"error": "Response timeout"}), 504

        except Exception as e:
            # 记录错误日志
            logger.error(f"处理HTTP请求时出错: {e}", exc_info=True)
            return jsonify({"error": f"Internal server error: {str(e)}"}), 500

    def meta(self) -> "PlatformMetadata":
        return PlatformMetadata(
            name="http_endpoint",
            description="HTTP ENDPOINT Adapter",
            id=self.config.get("id", "default"),
            adapter_display_name="HTTP ENDPOINT",
        )

    async def run(self):
        if self.future.done():
            self.future = asyncio.Future()
        else:
            self.future.cancel("重新启动")
            self.future = asyncio.Future()

        logger.info("HTTP ENDPOINT Adapter 正在启动...")
        self.api_register()
        self._running = True
        try:
            await self.future
        except asyncio.CancelledError as e:
            logger.info(f"HTTP ENDPOINT Adapter 取消运行: {e}")
        except Exception as e:
            logger.exception("HTTP ENDPOINT Adapter 运行异常", e)
        self._running = False
        logger.info("HTTP ENDPOINT Adapter 已结束运行。")

    def convert_message(self, data: dict) -> Optional[AstrBotMessage]:
        """将API消息转换为 AstrBotMessage"""
        try:
            msg_id = data.get('msg_id', self.generate_id())
            query = data.get('query', '')
            msg_type = data.get('type', '')
            url = data.get('url', '')
            sender_id = data.get('sender_id', '')
            sender_nickname = data.get('sender_nickname', '')

            hints = self.empty_check({'query': query, 'type': type, 'sender_id': sender_id})
            if hints:
                raise Exception(hints)

            abm = AstrBotMessage()
            abm.raw_message = data
            abm.message_id = msg_id
            abm.session_id = sender_id
            abm.self_id = 'http_endpoint_self_007'  # 机器人id固定
            # 处理消息类型
            abm.type = MessageType.FRIEND_MESSAGE

            # 消息类型：text、image、audio
            if msg_type == "text":
                abm.message = [Plain(query)]
                abm.message_str = query
            elif msg_type == "image":
                if not url:
                    raise Exception('图片url不能为空')
                abm.message = [Image.fromURL(url)]
                abm.message_str = "[图片]"
            else:
                logger.debug(f"忽略不支持的消息类型: {msg_type}")
                return None
            abm.sender = MessageMember(user_id=sender_id, nickname=sender_nickname)
            return abm
        except Exception as e:
            logger.error(f"转换消息时出错: {e}")
            return None

    async def handle_msg(self, message: Optional[AstrBotMessage]):
        """处理接收到的消息"""
        if not message:
            return
        try:
            event = HttpEndpointPlatformEvent(
                message_str=message.message_str,
                message_obj=message,
                platform_meta=self.meta(),
                session_id=message.session_id,
                adapter=self
            )

            self.commit_event(event)
        except Exception as e:
            logger.error(f"处理消息时出错: {e}")

    async def terminate(self):
        self._running = False
        # 停止adapter
        self.future.set_result("停止运行")
        # 移除api端点
        self.api_terminate()
        # 同步配置中的停止状态
        self.platform_config.update({"enable": False})
        astrbot_config.save_config()
        # todo 卸载加载adapter模块、隐藏消息平台中的adapter实例

    async def response_to(self, message_data: dict):
        """将消息发送到HTTP ENDPOINT"""
        try:
            msg_id = message_data.get('msg_id')

            if msg_id and msg_id in self._pending_requests:
                response_future = self._pending_requests[msg_id]
                if not response_future.done():
                    response_future.set_result(message_data)
                logger.info(f"http_endpoint 发送响应到 {msg_id}: {message_data}")
        except Exception as e:
            logger.error(f"发送消息到API失败: {e}")

    def generate_id(self, length=8):
        chars = string.ascii_letters + string.digits
        random_id = ''.join(secrets.choice(chars) for _ in range(length))
        return random_id

    def empty_check(self, fields: dict) -> list:
        """
        校验字典中的字段是否为空，返回所有空字段的提示信息
        :param fields: 待校验的字典（key=字段名，value=字段值）
        :return: 空字段提示列表（如["用户名不能为空", "手机号不能为空"]）
        空值规则：
        1. 值为 None
        2. 字符串类型且去除首尾空格后为空
        3. 列表/元组/集合类型且长度为 0
        4. 字典类型且无键值对（可选，如需启用取消下方注释）
        """
        empty_hints = []
        for field_name, field_value in fields.items():
            # 空值判断逻辑（和之前一致，封装在方法内部）
            is_empty = (
                    field_value is None
                    or (isinstance(field_value, str) and field_value.strip() == "")
                    or (isinstance(field_value, (list, tuple, set)) and len(field_value) == 0)
                    or (isinstance(field_value, dict) and len(field_value) == 0)
                #   or (isinstance(field_value, (int, float)) and field_value == 0)  # 可选：数字0视为空
            )
            if is_empty:
                empty_hints.append(f"{field_name}不能为空")
        return empty_hints

    def generate_jwt(self):
        payload = {
            "username": self.api_endpoint,
            "seek": self.seek,
        }
        jwt_token = astrbot_config.get('dashboard', {}).get('jwt_secret', '')
        if not jwt_token:
            raise ValueError("JWT secret is not set in the cmd_config.")
        token = jwt.encode(payload, jwt_token, algorithm="HS256")
        return token

    def token_check(self, auth_header:str):
        # 1. 提取 Authorization 请求头
        if not auth_header:
            raise ValueError("Authorization 请求头缺失")

        # 2. 拆分 Bearer 前缀（格式必须是 "Bearer <token>"）
        auth_parts = auth_header.split()
        if len(auth_parts) != 2 or auth_parts[0].lower() != "bearer":
            raise ValueError("Authorization 格式错误，需为 Bearer <token>")

        # 3. 获取 JWT 令牌字符串
        jwt_token = auth_parts[1]
        if not jwt_token:
            raise ValueError("JWT 令牌为空")

        try:
            jwt_secret = astrbot_config.get('dashboard', {}).get('jwt_secret', '')
            payload = jwt.decode(jwt=jwt_token, key=jwt_secret, algorithms=["HS256"])
            if self.seek != payload['seek']:
                raise ValueError("JWT 令牌已失效")
        except ExpiredSignatureError:
            raise ValueError("JWT 令牌已过期")
        except InvalidSignatureError:
            raise ValueError("JWT 签名无效（密钥错误或令牌被篡改）")
        except DecodeError:
            raise ValueError("JWT 格式错误，无法解码")
        except InvalidTokenError:
            raise ValueError("无效的 JWT 令牌")

    def _validate_config(self, config: dict):
        """验证配置参数"""
        # 验证核心必填配置项
        required_configs = {
            "api_endpoint": "",
        }

        for config_key, default_value in required_configs.items():
            value = config.get(config_key)
            if not value:
                logger.critical(
                    f"HTTP ENDPOINT Adapter 配置不完整，缺少 {config_key}。请检查配置文件。"
                )
                raise ValueError(
                    f"HTTP ENDPOINT Adapter 配置不完整：缺少必需的配置项 {config_key}"
                )
