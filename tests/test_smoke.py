import os
import tempfile
from pathlib import Path


def test_install_login_sources():
    with tempfile.TemporaryDirectory() as folder:
        os.environ['CBM_DATA'] = folder + '/data'
        os.environ['CBM_SOURCES'] = folder + '/sources'
        os.environ['CBM_ALLOW_HTTP'] = '1'
        Path(os.environ['CBM_SOURCES'], 'demo').mkdir(parents=True)
        from fastapi.testclient import TestClient
        from app.main import app
        with TestClient(app) as client:
            assert client.get('/api/bootstrap').json()['setup']
            password = 'not-for-production-2026'
            assert client.post('/api/setup', json={'username': 'admin', 'password': password}).status_code == 200
            assert client.post('/api/setup', json={'username': 'other', 'password': password}).status_code == 409
            response = client.post('/api/login', json={'username': 'admin', 'password': password})
            assert response.status_code == 200
            csrf = response.json()['csrf']
            assert client.post('/api/sources', json={'paths': ['demo']}).status_code == 403
            headers = {'x-csrf-token': csrf}
            assert client.post('/api/sources', headers=headers, json={'paths': ['demo']}).status_code == 200
            assert client.get('/api/status').json()['selected'] == ['demo']
            assert client.post('/api/sources', headers=headers, json={'paths': ['../../etc']}).status_code == 422
            assert client.post('/api/storage', headers=headers, json={'token': 'bad-token', 'folder': 'safe'}).status_code == 422
