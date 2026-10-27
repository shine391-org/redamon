"""Bounded thread pool for the agent's blocking Neo4j reads.

query_graph, graph_summary and the prior-chains read use the synchronous driver.
They run here rather than on asyncio's default executor, which also runs every
Bedrock LLM call (sync boto3 under run_in_executor) and the DNS lookup behind
every new outbound connection (asyncio getaddrinfo). A read stalled on an
overloaded Neo4j can hold its thread up to its transaction timeout, and a few
of those must not be able to starve the LLM or new tool connections.
"""

import asyncio
import functools
from concurrent.futures import ThreadPoolExecutor

_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="neo4j-read")


async def run_neo4j_read(fn, *args, **kwargs):
    """Run a blocking Neo4j read on the read pool and await its result."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_POOL, functools.partial(fn, *args, **kwargs))
