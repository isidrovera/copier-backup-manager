#!/usr/bin/env python3
"""Inventario Docker de solo consulta para Copier Backup Manager.

Ejecutar en el host Ubuntu con acceso autorizado a Docker. No utiliza
comandos que modifiquen contenedores, imágenes, volúmenes o redes.
No exporta variables de entorno, secretos ni contenido de archivos.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
LOG = logging.getLogger('cbm-agent')
TIMEOUT_SECONDS = 45
MAX_OBJECTS = 2000


def docker(*args):
    try:
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True,
            timeout=TIMEOUT_SECONDS, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Docker no disponible: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip()[:500])
    return result.stdout


def inspect(kind, names):
    if not names:
        return []
    # Batches to avoid oversized argv on hosts with many objects.
    items = []
    for offset in range(0, len(names), 50):
        batch = names[offset:offset + 50]
        data = json.loads(docker(kind, "inspect", *batch))
        if not isinstance(data, list):
            raise RuntimeError(f"Respuesta inesperada de Docker para {kind}")
        items.extend(data)
    return items


def list_ids(*args):
    output = docker(*args)
    ids = [line.strip() for line in output.splitlines() if line.strip()]
    if len(ids) > MAX_OBJECTS:
        raise RuntimeError("Demasiados objetos Docker; se requiere inventario por lotes")
    return ids


def trim(value, limit=400):
    return str(value or "")[:limit]


def container_info(item):
    config = item.get("Config") or {}
    state = item.get("State") or {}
    labels = config.get("Labels") or {}
    mounts = []
    for mount in item.get("Mounts") or []:
        mounts.append({
            "type": trim(mount.get("Type"), 30),
            "name": trim(mount.get("Name")),
            "source": trim(mount.get("Source"), 1024),
            "destination": trim(mount.get("Destination"), 1024),
            "read_only": not bool(mount.get("RW", False)),
        })
    ports = []
    for private, bindings in (item.get("NetworkSettings") or {}).get("Ports", {}).items():
        ports.append({
            "container_port": trim(private, 50),
            "host_bindings": [
                {"ip": trim(b.get("HostIp"), 80), "port": trim(b.get("HostPort"), 20)}
                for b in (bindings or [])
            ],
        })
    return {
        "id": trim(item.get("Id"), 64),
        "name": trim((item.get("Name") or "").lstrip("/")),
        "image": trim(config.get("Image"), 500),
        "status": trim(state.get("Status"), 50),
        "health": trim(((state.get("Health") or {}).get("Status")), 50),
        "compose_project": trim(labels.get("com.docker.compose.project")),
        "compose_service": trim(labels.get("com.docker.compose.service")),
        "compose_workdir": trim(labels.get("com.docker.compose.project.working_dir"), 1024),
        "compose_files": trim(labels.get("com.docker.compose.project.config_files"), 2048),
        "dokploy_managed": any("dokploy" in str(key).lower() for key in labels)
                           or "dokploy" in str(labels.get("com.docker.compose.project", "")).lower(),
        "mounts": mounts,
        "ports": ports,
    }


def volume_info(item):
    labels = item.get("Labels") or {}
    return {
        "name": trim(item.get("Name")),
        "driver": trim(item.get("Driver")),
        "mountpoint": trim(item.get("Mountpoint"), 1024),
        "compose_project": trim(labels.get("com.docker.compose.project")),
    }


def network_info(item):
    labels = item.get("Labels") or {}
    return {
        "id": trim(item.get("Id"), 64),
        "name": trim(item.get("Name")),
        "driver": trim(item.get("Driver")),
        "scope": trim(item.get("Scope")),
        "compose_project": trim(labels.get("com.docker.compose.project")),
    }


def image_info(item):
    return {
        "id": trim(item.get("Id"), 100),
        "tags": [trim(x, 500) for x in (item.get("RepoTags") or [])],
        "size_bytes": int(item.get("Size") or 0),
    }


def inventory():
    version = json.loads(docker("version", "--format", "{{json .Server}}"))
    containers = [container_info(x) for x in inspect("container", list_ids("ps", "-aq", "--no-trunc"))]
    volumes = [volume_info(x) for x in inspect("volume", list_ids("volume", "ls", "-q"))]
    networks = [network_info(x) for x in inspect("network", list_ids("network", "ls", "-q"))]
    images = [image_info(x) for x in inspect("image", list_ids("image", "ls", "-aq", "--no-trunc"))]
    projects = {}
    for c in containers:
        project = c["compose_project"]
        if project:
            entry = projects.setdefault(project, {
                "name": project, "compose_files": [], "workdirs": [], "containers": []
            })
            entry["containers"].append(c["name"])
            for path in c["compose_files"].split(","):
                if path and path not in entry["compose_files"]:
                    entry["compose_files"].append(path)
            if c["compose_workdir"] and c["compose_workdir"] not in entry["workdirs"]:
                entry["workdirs"].append(c["compose_workdir"])
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "hostname": trim(os.uname().nodename),
        "docker_version": trim(version.get("Version")),
        "containers": containers,
        "volumes": volumes,
        "networks": networks,
        "images": images,
        "compose_projects": sorted(projects.values(), key=lambda x: x["name"]),
        "notice": "Inventario informativo; no constituye un backup ni contiene secretos.",
    }


def atomic_save(destination, content):
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".inventory-", dir=str(destination.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(content, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description="Inventario Docker de solo consulta")
    parser.add_argument("--output", required=True, help="Archivo JSON de salida")
    args = parser.parse_args()
    LOG.info('Iniciando inventario Docker')
    try:
        data = inventory()
        atomic_save(Path(args.output).expanduser(), data)
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        LOG.error('No se pudo generar el inventario (%s). Verificar Docker y permisos.', type(exc).__name__)
        return 1
    LOG.info('Inventario publicado correctamente')
    LOG.info('Contenedores: %s', len(data['containers']))
    LOG.info('Proyectos Compose: %s', len(data['compose_projects']))
    LOG.info('Volúmenes: %s', len(data['volumes']))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
