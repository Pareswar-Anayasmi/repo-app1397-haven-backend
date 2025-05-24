from azure.cosmos.aio import CosmosClient
import os
COSMOS_ENDPOINT = os.getenv("COSMOS_ENDPOINT")
COSMOS_KEY = os.getenv("COSMOS_KEY")
DATABASE_NAME = os.getenv("DATABASE_NAME")


async def get_container_client(CONTAINER_NAME):
    client = CosmosClient(COSMOS_ENDPOINT, COSMOS_KEY)
    try:
        # Get database client
        database = client.get_database_client(DATABASE_NAME)

        # Get container client
        container = database.get_container_client(CONTAINER_NAME)
        
        return container
    except Exception as e:
        print(f"Error getting container client: {e}")
    finally:
        await client.close() 