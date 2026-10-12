"""Copier Backup Manager: servidor web y motor de copias de directorios autorizados.
No concede acceso automático al host ni al socket Docker.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

ROOT = Path(os.environ.get('CBM_DATA', '/data'))
SOURCE = Path(os.environ.get('CBM_SOURCES', '/sources'))
DB_PATH = ROOT / 'state.sqlite3'
LOCK = threading.Lock()
SESSION_SECONDS = 12 * 3600
TZ = ZoneInfo('America/Lima')
INVENTORY_PATH = Path('/inventory/docker.json')
MAX_INVENTORY_BYTES = 4 * 1024 * 1024
INVENTORY_MAX_AGE_SECONDS = 24 * 3600
app = FastAPI(title='Copier Backup Manager', docs_url=None, redoc_url=None)


def db():
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def init():
    ROOT.mkdir(parents=True, exist_ok=True)
    os.chmod(ROOT, 0o700)
    if not (ROOT / 'master.key').exists():
        fd = os.open(ROOT / 'master.key', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(Fernet.generate_key())
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS account(id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS config(name TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, operation TEXT NOT NULL, status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, detail TEXT NOT NULL DEFAULT '');
        ''')
    os.chmod(DB_PATH, 0o600)


def cipher():
    return Fernet((ROOT / 'master.key').read_bytes())


def put(key, value, secret=False):
    raw = cipher().encrypt(value.encode()).decode() if secret else value
    with db() as c:
        c.execute('INSERT INTO config(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=excluded.value', (key, raw))


def get(key, default='', secret=False):
    with db() as c:
        r = c.execute('SELECT value FROM config WHERE name=?', (key,)).fetchone()
    if not r:
        return default
    return cipher().decrypt(r['value'].encode()).decode() if secret else r['value']


def hash_password(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2**14, r=8, p=1).hex()


def account_exists():
    with db() as c:
        return c.execute('SELECT 1 FROM account WHERE id=1').fetchone() is not None


def require(request: Request, write=False):
    token = request.cookies.get('cbm_session', '')
    with db() as c:
        row = c.execute('SELECT csrf, expires FROM sessions WHERE token_hash=?', (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
    if not row or row['expires'] < int(time.time()):
        raise HTTPException(401, 'Inicia sesión para continuar')
    if write and not hmac.compare_digest(request.headers.get('x-csrf-token', ''), row['csrf']):
        raise HTTPException(403, 'Token CSRF inválido')
    return row


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=60)
    password: str = Field(min_length=12, max_length=256)


class Storage(BaseModel):
    token: str = Field(min_length=10)
    region: str = Field(default='global', pattern='^(global|eu)$')
    folder: str = Field(default='CopierBackupManager', min_length=1, max_length=180)


class Schedule(BaseModel):
    enabled: bool = False
    hour: int = Field(default=2, ge=0, le=23)
    minute: int = Field(default=0, ge=0, le=59)
    retention_days: int = Field(default=30, ge=1, le=3650)


class Selection(BaseModel):
    paths: list[str]


class Restore(BaseModel):
    snapshot: str = Field(min_length=8, max_length=100)


@app.get('/')
def home():
    return FileResponse(Path(__file__).parent / 'static' / 'index.html')


@app.get('/api/bootstrap')
def bootstrap(request: Request):
    if not account_exists():
        return {'setup': True, 'authenticated': False}
    try:
        require(request)
        return {'setup': False, 'authenticated': True, 'csrf': require(request)['csrf']}
    except HTTPException:
        return {'setup': False, 'authenticated': False}


@app.post('/api/setup')
def setup(body: Credentials, request: Request):
    # Atomic first-account creation to avoid two visitors claiming the installation.
    if not hmac.compare_digest(request.headers.get('host', '').split(':')[0], request.url.hostname or ''):
        raise HTTPException(400, 'Host inválido')
    salt = secrets.token_hex(16)
    with db() as c:
        try:
            c.execute('INSERT INTO account VALUES (1,?,?,?)', (body.username, salt, hash_password(body.password, salt)))
        except sqlite3.IntegrityError:
            raise HTTPException(409, 'La cuenta inicial ya fue creada')
    put('restic_password', secrets.token_urlsafe(48), secret=True)
    return {'ok': True}


@app.post('/api/login')
def login(body: Credentials):
    with db() as c:
        r = c.execute('SELECT * FROM account WHERE id=1').fetchone()
    if not r or not hmac.compare_digest(hash_password(body.password, r['salt']), r['password_hash']) or not hmac.compare_digest(body.username, r['username']):
        raise HTTPException(401, 'Usuario o contraseña incorrectos')
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    with db() as c:
        c.execute('DELETE FROM sessions WHERE expires < ?', (int(time.time()),))
        c.execute('INSERT INTO sessions VALUES (?,?,?)', (hashlib.sha256(token.encode()).hexdigest(), csrf, int(time.time()) + SESSION_SECONDS))
    response = JSONResponse({'ok': True, 'csrf': csrf})
    response.set_cookie('cbm_session', token, max_age=SESSION_SECONDS, httponly=True, secure=os.environ.get('CBM_ALLOW_HTTP') != '1', samesite='strict', path='/')
    return response


@app.post('/api/logout')
def logout(request: Request):
    require(request, True)
    with db() as c:
        c.execute('DELETE FROM sessions WHERE token_hash=?', (hashlib.sha256(request.cookies['cbm_session'].encode()).hexdigest(),))
    response = JSONResponse({'ok': True})
    response.delete_cookie('cbm_session')
    return response


def available_sources():
    if not SOURCE.exists():
        return []
    return sorted([p.name for p in SOURCE.iterdir() if p.is_dir() and not p.is_symlink()])


@app.get('/api/status')
def status(request: Request):
    require(request)
    with db() as c:
        runs = [dict(r) for r in c.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 30')]
    return {'sources': available_sources(), 'selected': json.loads(get('selected', '[]')),
            'storage_configured': bool(get('pcloud_token')),
            'folder': get('folder', 'CopierBackupManager'), 'region': get('region', 'global'),
            'schedule': json.loads(get('schedule', '{"enabled":false,"hour":2,"minute":0,"retention_days":30}')),
            'runs': runs, 'busy': LOCK.locked(), 'recovery_key_saved': (ROOT / 'master.key').exists()}


def read_docker_inventory():
    """Read a fixed, agent-generated inventory. Never communicate with Docker.

    An inventory is informational; it does not grant access to host paths,
    mounted volumes or container workloads.
    """
    empty = {
        'ready': False, 'stale': False, 'generated_at': None,
        'containers': [], 'volumes': [], 'networks': [],
        'images': [], 'compose_projects': [],
    }
    try:
        if not INVENTORY_PATH.is_file() or INVENTORY_PATH.is_symlink():
            return {**empty, 'message': 'El agente todavía no ha publicado su inventario'}
        info = INVENTORY_PATH.stat()
        if info.st_size <= 0 or info.st_size > MAX_INVENTORY_BYTES:
            raise ValueError('El archivo de inventario está vacío o excede 4 MiB')
        data = json.loads(INVENTORY_PATH.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or data.get('schema_version') != 1:
            raise ValueError('Versión o formato de inventario no compatible')
        names = ('containers', 'volumes', 'networks', 'images', 'compose_projects')
        if any(not isinstance(data.get(name), list) for name in names):
            raise ValueError('Inventario incompleto')
        if any(len(data[name]) > 2000 for name in names):
            raise ValueError('Inventario demasiado grande')
        timestamp = data.get('generated_at')
        if not isinstance(timestamp, str):
            raise ValueError('Fecha de generación ausente')
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError('La fecha debe incluir zona horaria')
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        if age < -300:
            raise ValueError('El inventario tiene una fecha futura inválida')
        # Ensure the payload cannot override the computed status or inject errors.
        allowed = ('schema_version', 'generated_at', 'hostname', 'docker_version',
                   'containers', 'volumes', 'networks', 'images', 'compose_projects', 'notice')
        output = {key: data[key] for key in allowed if key in data}
        stale = age > INVENTORY_MAX_AGE_SECONDS
        return {
            **output,
            'ready': True,
            'stale': stale,
            'age_seconds': max(0, int(age)),
            'message': 'El inventario necesita actualizarse' if stale else 'Inventario disponible',
        }
    except (OSError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        # This endpoint never reveals system paths or file contents on errors.
        return {**empty, 'message': f'No se pudo validar el inventario: {type(exc).__name__}'}


@app.get('/api/discovery')
def discovery(request: Request):
    require(request)
    return read_docker_inventory()


@app.get('/api/discovery/summary')
def discovery_summary(request: Request):
    require(request)
    data = read_docker_inventory()
    return {
        'ready': data['ready'], 'stale': data['stale'],
        'message': data['message'],
        'hostname': data.get('hostname'),
        'generated_at': data.get('generated_at'),
        'docker_version': data.get('docker_version'),
        'counts': {name: len(data[name]) for name in
                   ('containers', 'volumes', 'networks', 'images', 'compose_projects')},
    }


@app.post('/api/sources')
def select_sources(body: Selection, request: Request):
    require(request, True)
    possible = set(available_sources())
    if not body.paths or any(x not in possible for x in body.paths):
        raise HTTPException(422, 'Selecciona carpetas autorizadas de /sources')
    put('selected', json.dumps(sorted(set(body.paths))))
    return {'ok': True}


def rclone_conf():
    path = ROOT / 'rclone.conf'
    token = get('pcloud_token', secret=True)
    if not token:
        raise RuntimeError('Configura primero el acceso a pCloud')
    # Rclone pcloud requires an OAuth token JSON object (not password).
    # Sanitize before writing an ini-like configuration.
    token_obj = json.loads(token)
    if not isinstance(token_obj, dict) or not token_obj.get('access_token'):
        raise RuntimeError('Token OAuth de pCloud no válido')
    sanitized = json.dumps(token_obj, separators=(',', ':'))
    hostname = 'eapi.pcloud.com' if get('region') == 'eu' else 'api.pcloud.com'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(f'[pcloud]\ntype = pcloud\nhostname = {hostname}\ntoken = {sanitized}\n')
    return str(path)


@app.post('/api/storage')
def storage(body: Storage, request: Request):
    require(request, True)
    try:
        obj = json.loads(body.token)
    except ValueError:
        raise HTTPException(422, 'Pega el JSON OAuth obtenido con rclone authorize pcloud')
    if not isinstance(obj, dict) or not isinstance(obj.get('access_token'), str):
        raise HTTPException(422, 'El token OAuth debe contener access_token')
    folder = body.folder.strip().strip('/')
    if not folder or '..' in folder.split('/') or '\\' in folder or any(ord(c) < 32 for c in folder):
        raise HTTPException(422, 'Ruta de carpeta no válida')
    put('pcloud_token', json.dumps(obj), secret=True)
    put('region', body.region)
    put('folder', folder)
    return {'ok': True}


@app.post('/api/schedule')
def schedule(body: Schedule, request: Request):
    require(request, True)
    put('schedule', body.model_dump_json())
    return {'ok': True}


def command(*args, timeout=3600):
    env = os.environ.copy()
    env['RCLONE_CONFIG'] = rclone_conf()
    env['RESTIC_PASSWORD'] = get('restic_password', secret=True)
    return subprocess.run(list(args), env=env, capture_output=True, text=True, timeout=timeout, check=False)


def repository():
    return 'rclone:pcloud:' + get('folder', 'CopierBackupManager')


def restic(*args, timeout=14400):
    return command('restic', '-r', repository(), *args, timeout=timeout)


def short_error(proc):
    return (proc.stderr or proc.stdout or 'Comando terminado sin detalles')[-1800:]


def perform(operation, snapshot=None):
    if not LOCK.acquire(blocking=False):
        raise RuntimeError('Ya se está ejecutando una operación')
    with db() as c:
        job = c.execute('INSERT INTO runs(operation,status,started) VALUES (?,?,?)', (operation, 'running', now())).lastrowid
    try:
        if operation == 'test':
            p = command('rclone', 'lsd', 'pcloud:', timeout=90)
            if p.returncode:
                raise RuntimeError(short_error(p))
            detail = 'Conexión pCloud verificada'
        else:
            if not get('pcloud_token'):
                raise RuntimeError('Configura pCloud antes de respaldar')
            if operation == 'backup':
                paths = json.loads(get('selected', '[]'))
                valid = set(available_sources())
                if not paths or any(p not in valid for p in paths):
                    raise RuntimeError('No existen las carpetas seleccionadas; se rechazó un backup vacío')
                probe = restic('snapshots', '--json', timeout=90)
                if probe.returncode:
                    # Initializing only if `cat config` confirms missing repo; any other failure is not treated as empty.
                    check = restic('cat', 'config', timeout=90)
                    if check.returncode and ('Is there a repository' in check.stderr or 'does not exist' in check.stderr or 'unable to open config file' in check.stderr):
                        created = restic('init', timeout=90)
                        if created.returncode:
                            raise RuntimeError('No se pudo inicializar repositorio: ' + short_error(created))
                    else:
                        raise RuntimeError('No se puede acceder al repositorio existente: ' + short_error(probe))
                result = restic('backup', *[str(SOURCE / name) for name in paths], '--tag', 'copier-backup-manager')
            elif operation == 'check':
                result = restic('check', '--read-data-subset=5%')
            elif operation == 'restore':
                if not snapshot or not all(c in '0123456789abcdef' for c in snapshot.lower()):
                    raise RuntimeError('Identificador de snapshot inválido')
                target = ROOT / 'restored' / (datetime.now(TZ).strftime('%Y%m%d-%H%M%S') + '-' + snapshot[:8])
                target.mkdir(parents=True, exist_ok=False)
                result = restic('restore', snapshot, '--target', str(target))
            else:
                raise RuntimeError('Operación desconocida')
            if result.returncode:
                raise RuntimeError(short_error(result))
            detail = 'Completado' if operation != 'restore' else f'Recuperado en {target} (sin sobrescribir origen)'
        with db() as c:
            c.execute('UPDATE runs SET status=?, finished=?, detail=? WHERE id=?', ('success', now(), detail, job))
    except Exception as exc:
        with db() as c:
            c.execute('UPDATE runs SET status=?, finished=?, detail=? WHERE id=?', ('error', now(), str(exc)[:1800], job))
    finally:
        LOCK.release()


def launch(op, snapshot=None):
    if LOCK.locked():
        raise HTTPException(409, 'Existe otro trabajo en curso')
    threading.Thread(target=perform, args=(op, snapshot), daemon=True).start()
    return {'accepted': True}


@app.post('/api/jobs/{operation}')
def jobs(operation: str, request: Request):
    require(request, True)
    if operation not in ('backup', 'check', 'test'):
        raise HTTPException(404, 'Operación inexistente')
    return launch(operation)


@app.get('/api/snapshots')
def snapshots(request: Request):
    require(request)
    if LOCK.locked():
        raise HTTPException(409, 'Otro trabajo en ejecución')
    if not get('pcloud_token'):
        return []
    p = restic('snapshots', '--json', timeout=90)
    if p.returncode:
        raise HTTPException(400, 'No fue posible listar las copias: ' + short_error(p))
    return json.loads(p.stdout or '[]')


@app.post('/api/restore')
def restore(body: Restore, request: Request):
    require(request, True)
    return launch('restore', body.snapshot)


def scheduler_loop():
    while True:
        try:
            rule = json.loads(get('schedule', '{}'))
            current = datetime.now(TZ)
            date_key = current.strftime('%Y-%m-%d')
            if (rule.get('enabled') and current.hour == rule.get('hour') and current.minute == rule.get('minute')
                    and get('last_schedule_date') != date_key and not LOCK.locked()):
                put('last_schedule_date', date_key)
                threading.Thread(target=perform, args=('backup',), daemon=True).start()
        except Exception:
            pass
        time.sleep(20)


@app.on_event('startup')
def startup():
    init()
    threading.Thread(target=scheduler_loop, daemon=True).start()
