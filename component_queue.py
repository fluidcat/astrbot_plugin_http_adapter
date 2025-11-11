import asyncio
import time
from asyncio import Queue
from typing import Any, Awaitable, Callable, Dict, Hashable

from astrbot.core import logger as _logger


class KeyedSeqQueue:
    def __init__(
        self,
        key_func: Callable[[Any], Hashable],
        handler: Callable[[Any], Awaitable[None]],
        ttl: float = 30.0,
        scan: float = 10.0,
        q_max: int = 16,
    ):
        self.key_func = key_func
        self.handler  = handler
        self._ttl     = ttl
        self._scan    = scan
        self._q_max   = q_max

        self._queues: Dict[Any, Queue]        = {}
        self._tasks : Dict[Any, asyncio.Task] = {}
        self._last  : Dict[Any, float]        = {}
        self._epoch : Dict[Any, int]          = {}

        self._shutdown = False
        self._cleaner: asyncio.Task | None = None

    # ---------- 对外唯一入口 ----------
    async def put(self, item: Any) -> None:
        key = self.key_func(item)
        now = time.time()

        if key not in self._queues:
            q = Queue(maxsize=self._q_max)
            self._queues[key] = q
            self._last[key]   = now
            self._epoch[key]  = 0
            self._tasks[key]  = asyncio.create_task(self._worker(key))
        else:
            self._last[key]  = now
            self._epoch[key] += 1

        await self._queues[key].put(item)

    # ---------- 生命周期 ----------
    async def start(self) -> None:
        if self.handler is None:
            raise RuntimeError("handler not set")
        self._cleaner = asyncio.create_task(self._clean_idle())

    async def shutdown(self, timeout: float = 30) -> None:
        self._shutdown = True
        if self._cleaner:
            self._cleaner.cancel()
        for q in self._queues.values():
            await q.put(self._Sentinel.STOP)
        await asyncio.wait_for(
            asyncio.gather(*self._tasks.values(), return_exceptions=True),
            timeout=timeout,
        )
        _logger.info("shutdown finished")

    # ---------- 内部 ----------
    class _Sentinel:
        STOP = object()

    async def _clean_idle(self):
        while not self._shutdown:
            await asyncio.sleep(self._scan)
            now = time.time()
            for key in list(self._queues):
                if now - self._last[key] > self._ttl and self._queues[key].empty():
                    await self._queues[key].put((self._Sentinel.STOP, self._epoch[key]))

    async def _worker(self, key: Any):
        q     = self._queues[key]
        epoch = self._epoch[key]
        count = 0
        while True:
            item = await q.get()
            if item is self._Sentinel.STOP:
                break
            if isinstance(item, tuple) and item[0] is self._Sentinel.STOP:
                if item[1] == epoch and q.empty():
                    break
                continue

            await self.handler(item)
            count += 1

        del self._queues[key], self._tasks[key], self._last[key], self._epoch[key]
        _logger.debug("worker-%s removed after %d handled", key, count)