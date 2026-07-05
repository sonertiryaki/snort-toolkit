FROM python:3.11-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY frontend ./frontend

ENV DATA_DIR=/srv/data
RUN mkdir -p /srv/data

EXPOSE 8000

# Render/Railway gibi platformlar PORT ortam değişkenini kendileri atar;
# vermezlerse (ör. kendi sunucunuzda) varsayılan olarak 8000 kullanılır.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
