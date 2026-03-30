FROM python:3.10-slim

WORKDIR /app

# Copy dependency manifest first for layer caching
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

# Copy the full repository
COPY . ./

EXPOSE 8000

# Run FastAPI app
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8000"]
