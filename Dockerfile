# Dockerfile
FROM python:3.9-slim

# Ustawienie zmiennej środowiskowej PATH
ENV PATH="/root/.local/bin:$PATH"

# Ustawienie katalogu roboczego
WORKDIR /app

# Kopiowanie pliku requirements.txt i instalacja zależności
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Kopiowanie pozostałych plików aplikacji
COPY . .

# Ustawienie zmiennej środowiskowej Flask
ENV FLASK_APP=yourpackage
ENV FLASK_ENV=production

# Uruchomienie aplikacji Flask za pomocą Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "yourpackage:app"]