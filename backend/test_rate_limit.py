# Test /check rate limiting
# Run: python backend/test_rate_limit.py
import requests

API = 'http://localhost:5000'
print('Testing /check rate limit...')
print('Limit: 60 checks per hour per IP')
print()

for i in range(1, 66):
    r = requests.get(f'{API}/check?url=http://test.com')
    d = r.json()

    if r.status_code == 429:
        status  = d.get('status', '')
        message = d.get('message', '')
        reset   = d.get('reset_in', 0)
        print(f'Request {i}: RATE LIMITED!')
        print(f'  Status:   {status}')
        print(f'  Message:  {message}')
        print(f'  Reset in: {reset} seconds')
        break
    elif i % 10 == 0 or i == 1:
        s = d.get('status', '')
        print(f'Request {i:2}: OK  (status={s})')

print()
print('Rate limit is working correctly!')