from azure.cosmos.aio import CosmosClient
from dotenv import load_dotenv
import os
import aiohttp
load_dotenv()
# Replace with your actual Cosmos DB connection info
COSMOS_ENDPOINT = os.getenv("COSMOS_ENDPOINT")
COSMOS_KEY = os.getenv("COSMOS_KEY")

async def get_cosmos_client():
    """
    Creates and returns an asynchronous CosmosClient instance.
    The caller is responsible for closing it (using `async with` or calling `.close()`).
    """
    client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
    return client
