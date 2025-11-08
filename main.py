import asyncio
import importlib
import sys

from astrbot.api.star import Context, Star
from astrbot.api import logger
from astrbot.core import AstrBotConfig
from astrbot.core.platform import AstrMessageEvent
from astrbot.api.event import filter
from astrbot.core.star.filter.custom_filter import CustomFilter

from . import api_plugin_context

HttpEndpointAdapter = None
HttpEndpointPlatformEvent = None


class HttpEndpointAdapterFilter(CustomFilter):
    def __init__(self, raise_error: bool = True):
        super().__init__(raise_error)

    def filter(self, event: AstrMessageEvent, cfg: AstrBotConfig) -> bool:
        return event.get_platform_name() == 'http_endpoint'


class HttpEndpointPlugin(Star):

    def __init__(self, context: Context):
        super().__init__(context)
        self.context = context
        api_plugin_context.plugin_context = self.context

    async def initialize(self):
        # 强制预清理：在导入适配器前，无条件删除既有 http_endpoint 注册，确保干净状态
        try:
            modules = []
            try:
                import astrbot.api.platform.register as _api_reg
                modules.append(_api_reg)
            except Exception:
                pass
            try:
                import astrbot.core.platform.register as _core_reg
                modules.append(_core_reg)
            except Exception:
                pass
            for _m in modules:
                _map = getattr(_m, "platform_cls_map", None)
                try:
                    if _map is not None and ("http_endpoint" in _map):
                        del _map["http_endpoint"]
                        logger.debug("强制预清理：已移除 http_endpoint 既有注册。")
                except Exception:
                    pass
        except Exception:
            pass

        try:
            load_rest_api_modules()
        except ImportError as e:
            logger.error(f"导入 HTTP ENDPOINT Adapter 失败，请检查依赖是否安装: {e}")
            raise

    async def terminate(self):
        # 停用http_endpoint
        for p in self.context.platform_manager.get_insts():
            pm = p.meta()
            if pm.name == 'http_endpoint':
                await self.context.platform_manager.terminate_platform(pm.id)


def load_rest_api_modules(hot_reload: bool = True):
    """
    加载 REST API 相关模块（支持热加载）
    :param hot_reload: 是否清除缓存重新导入（热加载）
    """
    global HttpEndpointAdapter, HttpEndpointPlatformEvent

    try:
        adapter_module_name = "..http_endpoint_adapter"
        event_module_name = "..http_endpoint_event"

        # 1. 处理 http_endpoint_adapter 模块
        if hot_reload and adapter_module_name in sys.modules:
            del sys.modules[adapter_module_name]
            logger.info("清除 http_endpoint_adapter 缓存，触发热加载")

        # 动态导入模块（支持相对路径）
        adapter_module = importlib.import_module(adapter_module_name, package=__name__)
        # 执行初始化函数
        adapter_module._inject_astrbot_field_metadata()
        # 赋值给全局变量
        HttpEndpointAdapter = adapter_module.HttpEndpointAdapter

        # 2. 处理 http_endpoint_event 模块
        if hot_reload and event_module_name in sys.modules:
            del sys.modules[event_module_name]
            logger.info("清除 http_endpoint_event 缓存，触发热加载")

        event_module = importlib.import_module(event_module_name, package=__name__)
        HttpEndpointPlatformEvent = event_module.HttpEndpointPlatformEvent

        logger.info("HTTP ENDPOINT 模块加载成功（热加载：%s）", hot_reload)

    except ImportError as e:
        logger.error(f"导入 HTTP ENDPOINT Adapter 失败，请检查依赖是否安装: {e}")
        # 重置全局变量，避免状态不一致
        HttpEndpointAdapter = None
        HttpEndpointPlatformEvent = None
        raise
