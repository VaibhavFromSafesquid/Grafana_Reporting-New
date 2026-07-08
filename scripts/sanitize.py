#!/usr/bin/env python3
import os, sys

REPLACE = [
    ('SqKnv1M=kuZkOyJjgY78', '<ES_PASSWORD>'),
    ('Sarva@1234', '<GRAFANA_ADMIN_PASSWORD>'),
    ('10.200.2.141', '<REPORTING_SERVER_IP>'),
    ('10.200.2.137', '<PROXY_SERVER_IP_3>'),
    ('10.200.2.133', '<PROXY_SERVER_IP_1>'),
    ('10.200.2.132', '<PROXY_SERVER_IP_2>'),
    ('10.200.2.126', '<CLIENT_INTERNAL_IP>'),
]
EXCLUDE_DIRS = {'.git', '__pycache__'}
EXCLUDE_FILES = {'sanitize.py', 'prepush-verify.sh'}
def walk_files():
    for r, ds, fs in os.walk('.'):
        ds[:] = [d for d in ds if d not in EXCLUDE_DIRS]
        for f in fs:
            if f in EXCLUDE_FILES: continue
            yield os.path.join(r, f)
total = 0; per = {}
for p in walk_files():
    try:
        raw = open(p, 'rb').read()
        txt = raw.decode('utf-8')
    except Exception:
        continue
    new = txt; c = 0
    for r, ph in REPLACE:
        n = new.count(r)
        if n:
            new = new.replace(r, ph); c += n
    if c:
        open(p, 'w').write(new); per[p] = c; total += c
print(f'Sanitized {total} occurrences across {len(per)} files:')
for p, n in sorted(per.items()):
    print(f'  {n:4d}  {p}')
missed = []
for p in walk_files():
    try:
        txt = open(p, 'rb').read().decode('utf-8')
    except Exception:
        continue
    for r, _ in REPLACE:
        if r in txt: missed.append((p, r))
if missed:
    print(''); print('FAIL: secrets still present after sanitization:')
    for p, r in missed:
        r2 = r[:4]+'***'+r[-2:] if len(r)>8 else '***'
        print(f'  {p}: still contains {r2}')
    sys.exit(1)
print(''); print('OK: sanitization pass verified clean')
