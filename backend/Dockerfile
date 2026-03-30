FROM python:3.11-slim

# tshark is NOT installed at build time because apt-get often fails
# due to network restrictions in the build environment.
# Instead, entrypoint.sh installs it at container startup when needed.

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
