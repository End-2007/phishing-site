import sys
sys.path.insert(0, 'src')
from predict import predict

urls = [
    'http://update-system.com',
    'http://10.0.0.1/admin',
    'http://192.168.1.1',
    'http://test-suspicious.xyz',
    'http://verify-info.net',
]

for u in urls:
    r = predict(u)
    print(f"{r['verdict']:12s} | {r['risk_score']:3d}/100 | {u}")
