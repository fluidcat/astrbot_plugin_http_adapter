from typing import TYPE_CHECKING

from astrbot.api import logger
from astrbot.api.event import AstrMessageEvent, MessageChain
from astrbot.api.message_components import Image, Plain
from astrbot.api.platform import AstrBotMessage, PlatformMetadata

if TYPE_CHECKING:
    from .http_endpoint_adapter import HttpEndpointAdapter


class HttpEndpointPlatformEvent(AstrMessageEvent):
    def get_message_outline(self) -> str:
        """重写此方法以规避核心框架的遍历问题，安全生成消息概要。
        兼容 self.message_obj.message 既可能是 MessageChain 也可能是 list 的情况。
        """
        if not self.message_obj or not self.message_obj.message:
            return ""

        # 核心修复：确保在遍历前调用 .get_chain()
        chain = self.message_obj.message
        if isinstance(chain, MessageChain):
            iterable_chain = chain.chain
        else:  # 如果它已经是列表，则直接使用
            iterable_chain = chain

        outline_parts = []
        for item in iterable_chain:
            if isinstance(item, Plain):
                outline_parts.append(item.text)
            elif isinstance(item, Image):
                outline_parts.append("[图片]")
            else:
                outline_parts.append(f"[{item.__class__.__name__}]")

        return " ".join(outline_parts).strip()

    def __init__(
        self,
        message_str: str,
        message_obj: AstrBotMessage,
        platform_meta: PlatformMetadata,
        session_id: str,
        adapter: "HttpEndpointAdapter",  # 改为持有适配器实例
    ):
        super().__init__(message_str, message_obj, platform_meta, session_id)
        self.adapter = adapter  # 保存适配器实例

    async def send(self, message: MessageChain):
        """发送消息到HTTP ENDPOINT：
        - 合并连续的文本段为单条消息
        - 图片作为URL发送
        """
        # 获取消息ID用于回复
        msg_id = self.message_obj.message_id

        resp = []
        response_body = {"msg_id": msg_id, 'data': resp}

        # 核心修复：确保在遍历前获取可迭代列表
        chain = message.chain
        for item in chain:
            if isinstance(item, Plain):
                resp.append({"type": "text", "content": item.text})
            elif isinstance(item, Image):
                if hasattr(item, "url") and item.url:
                    resp.append({"type": "image", "content": item.url})
                elif hasattr(item, "path") and item.path:
                    # todo 本地图片转url
                    logger.warning("暂不支持发送本地图片文件")
                else:
                    logger.warning("图片消息缺少URL或路径信息")
            else:
                logger.warning(f"忽略不支持的消息组件: {item.__class__.__name__}")
        await super().send(message)
        await self.adapter.response_to(response_body)

