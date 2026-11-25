
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src ./src
ENV FLASK_APP=src/app.py
# SECRET_KEY is NOT baked into the image (CWE-798); pass it at runtime: docker run -e SECRET_KEY=...
RUN useradd -r -u 10001 appuser && mkdir /data && chown appuser /data
USER appuser
ENV DB_PATH=/data/demo.sqlite3
EXPOSE 5000
CMD ["sh", "-c", "python src/db.py && flask run --host=0.0.0.0 --port=5000"]
