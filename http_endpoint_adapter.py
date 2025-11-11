import asyncio
import secrets
import string
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import Optional, Any

import aiohttp
import jwt
from aiohttp.client import ClientTimeout
from cachetools import TTLCache
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
from astrbot.core.message.message_event_result import MessageChain
from astrbot.core.platform.message_session import MessageSesion
from .component_queue import KeyedSeqQueue
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
            "hep_api_endpoint": {
                "description": "API端点URL",
                "type": "string",
                "hint": "必填项。HTTP ENDPOINT的基地址。",
                "obvious_hint": True,
            },
            "hep_api_key": {
                "description": "API密钥",
                "type": "string",
                "hint": "用于API认证的密钥，只读不可修改，需要更新请【清空或修改seek】",
            },
            "hep_seek": {
                "description": "seek",
                "type": "string",
                "hint": "seek，自动生成，清空会自动生成并重置api_key",
            },
            "hep_callback_switch": {
                "description": "消息回调开关",
                "type": "bool",
                "hint": "消息回调开关，开启后响应缓存则失效",
            },
            "hep_callback_url": {
                "description": "消息回调URL",
                "type": "string",
                "hint": "消息回调开关开启时必填",
                "obvious_hint": True,
            },
            "hep_cache_size": {
                "description": "请求响应缓存大小",
                "type": "string",
                "hint": "接口响应缓存，在高并发场景下缓存过小会导致缓存数据提前过期",
            },
            "hep_cache_ttl": {
                "description": "响应缓存有效时间",
                "type": "string",
                "hint": "单位：秒",
            },
        }

        # 仅在缺失时新增；若已存在则尽量补齐缺失的字段
        for k, v in adapter_config.items():
            items[k] = v

        logger.debug("已为 HTTP ENDPOINT 适配器注入字段元数据")
    except Exception as e:
        try:
            logger.debug(f"注入 HTTP ENDPOINT 字段元数据失败: {e}")
        except Exception:
            pass


@dataclass
class RespMsg:
    msg_id: str = ""
    data: list[dict] = field(default_factory=list)
    detail: Optional[str] = "success"
    code: int = 0
    
    def build(self, msg_id: str = "", data: list = [], detail: str = "success", code: int = 0) -> "RespMsg":
        self.msg_id = msg_id
        self.data = data
        self.detail = detail
        self.code = code
        return self

    def ok(self, msg_id, data) -> "RespMsg":
        self.msg_id = msg_id
        self.data = data
        return self
    
    def error(self, detail, msg_id: str="", code: int = 500) -> "RespMsg":
        self.msg_id = msg_id
        self.detail = detail
        self.code = code
        return self

@register_platform_adapter(
    "http_endpoint",
    "HTTP ENDPOINT Adapter",
    default_config_tmpl={
        "id": "http_endpoint",
        "type": "http_endpoint",
        "enable": False,
        "hint": "HTTP ENDPOINT适配器：通过HTTP API接收和发送消息。",
        "hep_api_endpoint": "/v1/chat",
        "hep_api_key": "",
        "hep_seek": "",
        "hep_callback_switch": False,
        "hep_callback_url": "",
        "hep_cache_size": "4096",
        "hep_cache_ttl": "300",
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
        logger.debug("HTTP ENDPOINT Adapter 正在初始化...")

        self.config = platform_config
        self.settings = platform_settings
        self.api_endpoint = platform_config.get("hep_api_endpoint", "/v1/chat")
        self.api_key = platform_config.get("hep_api_key", "")
        self.seek = platform_config.get("hep_seek", "")

        self.cache_size = platform_config.get("hep_cache_size", "4096")
        self.cache_ttl = platform_config.get("hep_cache_ttl", "300")

        self.callback_url = platform_config.get("hep_callback_url")
        self.callback_switch = platform_config.get("hep_callback_switch", False)
        self.callback_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)
        )

        # 存储待处理的HTTP请求
        self._pending_requests = {}
        self.cache_responses = TTLCache(maxsize=int(self.cache_size), ttl=int(self.cache_ttl))
        self.callback_queue: KeyedSeqQueue = KeyedSeqQueue(key_func=lambda x: x.msg_id, handler=self.callback_handler)

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
            self.platform_config.update({"hep_seek": self.seek})
            astrbot_config.save_config()
        elif self.api_key:
            try:
                # 验证seek是否被修改
                self.token_check(self.api_key)
            except:
                self.api_key = None
        if not self.api_key:
            self.api_key = self.generate_jwt()
            self.platform_config.update({"hep_api_key": self.api_key})
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
            auth_header = request.headers.get("Authorization", "")
            self.token_check(auth_header)
        except Exception as e:
            return jsonify(RespMsg().error(detail="Invalid Authorization", code=401)), 401

        try:
            # 获取请求数据
            request_data = await request.get_json()
            # 验证请求数据
            if not request_data:
                return jsonify(RespMsg().error(detail="Invalid JSON data", code=400)), 400

            message = self.convert_message(request_data)
            # 请求ID
            msg_id = message.message_id

            # 检查缓存，有缓存则直接返回缓存数据
            if not self.callback_switch and (resp := self.cache_responses.get(msg_id)):
                return jsonify(RespMsg().ok(msg_id, resp)), 200

            if self._pending_requests.get(msg_id):
                return jsonify(RespMsg().build(msg_id, detail=f"request: {msg_id} 正在处理中")), 202

            # 创建Future对象用于存储响应
            response_future = asyncio.Future()

            # 将请求ID和Future存储在适配器中
            self._pending_requests[msg_id] = response_future

            if message:
                # 直接处理消息
                await self.handle_msg(message)

            if self.callback_switch:
                return jsonify(RespMsg().ok(msg_id, [])), 200

            # 等待响应
            try:
                # 设置超时时间，避免无限等待
                await asyncio.wait_for(response_future, timeout=30.0)

                # 清理Future
                if msg_id in self._pending_requests:
                    del self._pending_requests[msg_id]

                # 返回响应数据
                if resp := self.cache_responses.get(msg_id):
                    return jsonify(RespMsg().ok(msg_id, resp)), 200
                else:
                    return jsonify(RespMsg().ok(msg_id, [])), 200
            except asyncio.TimeoutError:
                # 清理超时的Future
                if msg_id in self._pending_requests:
                    del self._pending_requests[msg_id]
                return jsonify(RespMsg().build(msg_id, detail=f"request: {msg_id} 正在处理中")), 202

        except Exception as e:
            # 记录错误日志
            logger.error(f"处理HTTP请求时出错: {e}", exc_info=True)
            return jsonify(RespMsg().error(detail=f"Internal server error: {str(e)}", code=500)), 500

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
        # 启动回调队列
        if self.callback_switch:
            await self.callback_queue.start()

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

            hints = self.empty_check({'query': query, 'type': msg_type, 'sender_id': sender_id})
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
        logger.info("HTTP ENDPOINT Adapter 正在清理资源...")
        self._running = False
        # 停止adapter
        self.future.set_result("停止运行")
        # 移除api端点
        self.api_terminate()
        # 同步配置中的停止状态
        self.platform_config.update({"enable": False})
        astrbot_config.save_config()

        await self.callback_queue.shutdown()
        await self.callback_session.close()
        # todo 卸载加载adapter模块、隐藏消息平台中的adapter实例

    async def send_by_session(
            self,
            session: MessageSesion,
            message_chain: MessageChain,
    ) -> Awaitable[Any]:
        """
        先缓存数据，等待客户端请求时，一起返回
        """
        contents = self.extract_message(message_chain)
        if not contents:
            return None
        session_id = f'session:{session.session_id}'
        _cache = self.cache_responses.get(session_id, [])
        _cache.extend(contents)
        self.cache_responses.update({session_id: _cache})

        # 推送到callback队列
        await self.push_callback_queue(session_id, contents)

    async def response_to(self, req_msg: AstrBotMessage, message: MessageChain):
        """将消息发送到HTTP ENDPOINT"""
        msg_id = req_msg.message_id

        try:
            session_content = []
            reqrep_content = self.extract_message(message)

            # 推送到callback队列
            await self.push_callback_queue(msg_id, reqrep_content)

            # 发送到http缓存
            ## 添加会话级的主动数据
            session_id = f'session:{req_msg.session_id}'
            if session_msg := self.cache_responses.get(session_id, []):
                session_content.extend(session_msg)

            ## 添加请求级别被动数据
            _cache = self.cache_responses.get(msg_id, [])
            _cache.extend(session_content)
            _cache.extend(reqrep_content)
            self.cache_responses.update({msg_id: _cache})

            if msg_id and msg_id in self._pending_requests:
                response_future = self._pending_requests[msg_id]
                del self._pending_requests[msg_id]
                if not response_future.done():
                    response_future.set_result(reqrep_content)
            logger.info(f"http_endpoint 缓存响应到 {msg_id}: {reqrep_content}")

        except Exception as e:
            logger.error(f"发送消息到API失败: {e}")

    async def push_callback_queue(self, msg_id: str, data: list[dict]):
        """将消息发送到callback队列"""
        if self.callback_switch and self.callback_url:
            await self.callback_queue.put(RespMsg().ok(msg_id, data))

    async def callback_handler(self, msg: RespMsg):
        logger.debug(f"callback_handler: {msg}")
        if not self.callback_url:
            logger.error("callback_url 为空，无法发送回调")
            return
        for attempt in range(1, 3):
            try:
                async with self.callback_session.post(
                        self.callback_url, json=msg.__dict__, timeout=ClientTimeout(total=10)) as resp:
                    resp.raise_for_status()
                return
            except Exception as e:
                await asyncio.sleep(2 ** (attempt - 1))

    def extract_message(self, message: MessageChain):
        content = []
        chain = message.chain
        for item in chain:
            if isinstance(item, Plain):
                content.append({"item_id": self.generate_id(length=10), "type": "text", "content": item.text})
            elif isinstance(item, Image):
                if hasattr(item, "url") and item.url:
                    content.append({"item_id": self.generate_id(length=10), "type": "image", "content": item.url})
                elif hasattr(item, "path") and item.path:
                    # todo 本地图片转url
                    logger.warning("暂不支持发送本地图片文件")
                else:
                    logger.warning("图片消息缺少URL或路径信息")
            else:
                logger.warning(f"忽略不支持的消息组件: {item.__class__.__name__}")
        return content

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

    def token_check(self, auth_header: str):
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

