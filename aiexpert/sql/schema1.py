# main.py

import asyncio
import aiohttp
from azure.cosmos import PartitionKey, exceptions
from .connection1 import get_cosmos_client  # Import your client creator
from dotenv import load_dotenv
import os 
load_dotenv()
DATABASE_NAME = os.getenv("DATABASE_NAME")

# Define multiple containers with their respective partition keys
CONTAINERS = [
    {"id": "conversation_summary", "partition_key": "/id"},
    {"id": "assistants", "partition_key": "/id"},
    {"id": "assistant_permissions", "partition_key": "/id"},
    {"id": "authen_tokens", "partition_key": "/id"},
    {"id": "organization_groups", "partition_key": "/id"},
    {"id": "group_users", "partition_key": "/id"},
    {"id": "users", "partition_key": "/id"},
    
]

async def init():
    client = await get_cosmos_client()

    async with client:
        try:
            # Create database if it doesn't exist
            db = await client.create_database_if_not_exists(id=DATABASE_NAME)
            print(f"Database '{DATABASE_NAME}' ready.")

            # Create all containers from the list
            for container_def in CONTAINERS:
                container_id = container_def["id"]
                partition_key_path = container_def["partition_key"]

                container = await db.create_container_if_not_exists(
                    id=container_id,
                    partition_key=PartitionKey(path=partition_key_path),
                    offer_throughput=400
                )
                print(f"Container '{container_id}' with partition key '{partition_key_path}' ready.")

        except exceptions.CosmosHttpResponseError as e:
            print(f"Cosmos DB error: {e.message}")
