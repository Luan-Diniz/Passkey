# Create Virtual Environment
python3 -m venv ./services/venv 

# Run server
docker compose up -d

# Run client
./run_client.sh

# Useful for developers:
    docker compose down -v               (Deletes database volume!)
    docker compose up --build --force-recreate 