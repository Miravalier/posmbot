FROM python:3.10
ENV PYTHONUNBUFFERED=1
RUN pip install requests twitchAPI

COPY ./src /app
WORKDIR /app
CMD ["python3", "main.py"]
