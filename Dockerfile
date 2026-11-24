FROM node:20-bookworm-slim AS email-crawler-builder

WORKDIR /build/email-crawler
COPY data/tools/email-crawler/package.json ./package.json
COPY data/tools/email-crawler/dist ./dist
RUN npm install --omit=dev --ignore-scripts


FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=email-crawler-builder /usr/local/bin/node /usr/local/bin/node
COPY --from=email-crawler-builder /build/email-crawler/node_modules /opt/phishpanel-email-crawler/node_modules

COPY requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt \
    && python -m playwright install --with-deps chromium

COPY app ./app
COPY demo ./demo
COPY run.py ./
COPY data/tools/email-crawler/package.json /opt/phishpanel-email-crawler/package.json
COPY data/tools/email-crawler/dist /opt/phishpanel-email-crawler/dist
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

VOLUME ["/app/data"]
EXPOSE 8000

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
