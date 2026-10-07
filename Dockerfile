FROM python:3.13-slim@sha256:9d2e5553305c7c7b0097999bb17187c69b921ccd6bc9d40e4bb5ebe652c00285
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev linux-libc-dev strace \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/agentprof
COPY native native
RUN gcc -O2 -Wall -Wextra -Werror native/sandbox.c -o /usr/local/bin/agentprof-sandbox
COPY agentprof agentprof
COPY benchmarks benchmarks
ENV PYTHONPATH=/opt/agentprof PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "agentprof"]
