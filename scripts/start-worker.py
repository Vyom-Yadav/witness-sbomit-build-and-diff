#!/usr/bin/env python3
"""Start the Temporal worker for SBOMit Accuracy Analyzer."""

import asyncio

from src.orchestrator.client import start_worker


async def main():
    """Start the Temporal worker."""
    await start_worker()


if __name__ == "__main__":
    asyncio.run(main())
