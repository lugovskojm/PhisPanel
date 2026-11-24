#!/bin/sh
set -eu

mkdir -p /app/data/tools
rm -rf /app/data/tools/email-crawler
cp -a /opt/phishpanel-email-crawler /app/data/tools/email-crawler

exec "$@"
