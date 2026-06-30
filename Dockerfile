FROM python:3.10-slim

# Установка необходимых системных утилит (включая nsenter)
RUN apt-get update && apt-get install -y --no-install-recommends \
    util-linux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Копирование и установка зависимостей
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование исходного кода
COPY . .

# Создаем папку для хранения базы данных
RUN mkdir -p /app/data

EXPOSE 5002

# Запуск приложения
CMD ["python", "app.py"]
