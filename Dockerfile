FROM python:3.7-slim

WORKDIR .

COPY requirements.txt requirements.txt
COPY auth_service/main.py main.py

RUN pip install -r requirements.txt

CMD ["python", "-u", "main.py"]
