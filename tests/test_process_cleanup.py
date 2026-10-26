"""D398: closing the MCP subprocess owner must close unread pipe transports."""
from __future__ import annotations

import asyncio
import subprocess
import sys

import anyio


def test_process_close_releases_unread_stdout_before_loop_exit():
    async def exercise():
        process = await anyio.open_process(
            [sys.executable, "-u", "-c",
             "import sys; sys.stdout.buffer.write(b'x' * 132000); sys.stdout.flush()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        # Inspect ownership without reading away the buffered condition. This is
        # the actual asyncio transport used by AnyIO and the MCP stdio client.
        transport = process._process._transport
        try:
            with anyio.fail_after(15):
                while process.returncode is None:
                    await anyio.sleep(0.01)
            assert process.returncode == 0
            await process.aclose()
            assert all(transport.get_pipe_transport(fd).is_closing() for fd in range(3))
        finally:
            # A failing regression must still release its own diagnostic child;
            # this cleanup occurs after, and cannot satisfy, the assertion.
            transport.close()
            await process.wait()
            await anyio.sleep(0)

    asyncio.run(exercise())
