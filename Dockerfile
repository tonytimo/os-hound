FROM python:3.11-slim-bookworm AS base
WORKDIR /app

ADD requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


FROM python:3.11-slim-bookworm AS runtime
COPY --from=base /usr/local/lib/python3.11 /usr/local/lib/python3.11

WORKDIR /app
COPY os_hound /app/os_hound

ENTRYPOINT ["/bin/bash"]

