# Dockerfile
FROM python:3.9-slim

ENV PATH="/root/.local/bin:$PATH"

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN pip install python-dotenv

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "yourpackage:app"]