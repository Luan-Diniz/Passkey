FROM python:latest

WORKDIR /server_api

COPY *.py .
COPY ./requirements.txt .

RUN pip install -r requirements.txt

EXPOSE 5000

CMD ["python", "server_api.py"]