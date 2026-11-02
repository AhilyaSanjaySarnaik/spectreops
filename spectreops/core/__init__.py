# in Executor.__init__
from .rate_limit import RateLimiter
self.limiter = RateLimiter(rate_limit, concurrency)   # pass from policy

# in Executor.run, around the handler call:
network_tools = {"http_probe", "nmap_scan", "nuclei_scan", "dir_brute",
                 "subfinder_enum", "openapi_endpoints"}
if name in network_tools:
    await self.limiter.acquire()
    try:
        result = await asyncio.wait_for(tool.handler(args), timeout=self.max_timeout)
    finally:
        self.limiter.release()
else:
    result = await asyncio.wait_for(tool.handler(args), timeout=self.max_timeout)
