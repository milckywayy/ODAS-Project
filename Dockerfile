FROM python:3.11

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

ENV FLASK_APP=app:create_app

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
