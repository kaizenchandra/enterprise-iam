#!/usr/bin/env python3
"""Acquire a service token and call the API without printing credentials or tokens."""
import base64
import json
import os
import urllib.parse

issuer = os.environ.get('IAM_ISSUER', 'http://localhost:9000')
auth = base64.b64encode(('order-service:' + os.environ['MACHINE_SECRET']).encode()).decode()
request = urllib.request.Request(issuer + '/oauth2/token', data=urllib.parse.urlencode(
    {'grant_type': 'client_credentials', 'scope': 'orders.read'}).encode(), headers={'Authorization': 'Basic ' + auth})
with urllib.request.urlopen(request, timeout=5) as response: token = json.load(response)['access_token']
with urllib.request.urlopen(
        urllib.request.Request('http://localhost:9001/api/orders', headers={'Authorization': 'Bearer ' + token}),
        timeout=5) as response: print(response.read().decode())
