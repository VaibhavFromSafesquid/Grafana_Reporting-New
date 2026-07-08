# Grafana Reporting - HDFC Deployment Snapshot

Snapshot of the working SafeSquid + Elasticsearch + Logstash + Grafana
reporting stack as deployed for HDFC. This repo is a recovery/reference
point, not an installer. For a fresh deployment, use the separate
`hdfc-deploy-package.zip` when available.

## Layout

- `dashboards/`         Grafana dashboard JSONs, exported from the live server
- `logstash/`           Live Logstash pipeline config and index templates
- `elasticsearch/`      ES ingest pipeline (perf numeric conversion) and cluster settings
- `export-api/`         Flask export API app.py and systemd unit
- `scripts/`            Sanitization + pre-push verification

## Secrets

Every real secret (ES password, Grafana admin password, internal IPs)
has been replaced with `<PLACEHOLDER>` tokens. See `.env.example`
for the full list. On redeployment, replace the placeholders with real
values from your `.env`.

## Never commit real secrets

`scripts/sanitize.py` normalizes files back to placeholders.
`scripts/prepush-verify.sh` is a blocking independent scan.
Run both before every commit if you touch files under this repo.
