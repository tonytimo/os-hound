FROM python:3.11-alpine

RUN mkdir -p /home/app

COPY . /home/app

WORKDIR /home/app

RUN pip install poetry

RUN poetry install

CMD ["tail", "-f", "/dev/null"]
