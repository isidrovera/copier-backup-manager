# Copier Backup Manager v0.2 (prototipo funcional)

Panel web en español, instalación inicial, autenticación, selección de carpetas autorizadas, almacenamiento pCloud mediante Rclone, backups cifrados e incrementales con Restic, programación diaria, historial, verificación y restauración **en carpeta aislada**.

## Advertencias importantes

- **NO es un respaldo de Ubuntu completo ni de Dokploy**. No realiza backups de bases de datos PostgreSQL consistentes ni snapshots de volúmenes Docker. Eso requiere un agente del host, hooks específicos y validación de restauración.
- No montar `/`, `/var/run/docker.sock`, archivos de credenciales ni el directorio completo del host en esta versión.
- **No utilizar todavía como el único respaldo de producción.** El proyecto necesita revisión de seguridad y pruebas en un VPS de laboratorio.
- Usa HTTPS obligatorio (Dokploy/Traefik). El primer visitante podría crear el administrador si publicas el servicio sin haber configurado el usuario: **restringe el acceso al panel durante la instalación inicial**.
- El volumen `cbm_data` contiene la base de datos, claves, contraseñas de Restic y configuración cifrada: haz backup del volumen y exporta a un gestor de contraseñas la contraseña del repositorio Restic. Si pierdes el volumen o su clave, las copias pueden resultar irrecuperables. La futura función de exportación segura está pendiente.

## Despliegue desde GitHub/Dokploy

1. Publica el contenido de este proyecto en un repositorio GitHub (sin secretos) y crea una app Docker Compose en Dokploy apuntando a `compose.yaml`.
2. Despliega con la aplicación restringida a una red privada o autenticación adicional mientras creas el usuario administrador. Usa un dominio HTTPS.
3. El Compose monta exclusivamente `./sample-data` en `/sources/demo` **solo para pruebas**. Reemplázalo por rutas expresamente permitidas con `:ro` cuando tengas un agente seguro.
4. Entra al panel, crea el administrador (contraseña 12+ caracteres), selecciona carpeta de prueba y configura pCloud.
5. Desde una PC con Rclone ejecuta `rclone authorize pcloud` (autoriza tu cuenta de forma interactiva) y pega el JSON OAuth obtenido en la página **pCloud**. Selecciona región global/eu según corresponda.
6. Verifica conexión, ejecuta un respaldo de pruebas y restaura a destino aislado para confirmar integridad.

**Nota técnica:** En versiones recientes de Rclone el token OAuth puede cambiar con su renovación; la persistencia de token refrescado y reconexión web guiada debe implementarse antes de usarlo desatendido durante meses. En esta v0.2 no se garantiza renovación persistente del token.

## Datos persistentes

- `/data/state.sqlite3`: usuarios, configuraciones, registros.
- `/data/master.key`: clave de cifrado local (perderla hace inaccesibles tokens cifrados).
- `/data/restored`: recuperaciones aisladas.
- `/sources`: exclusivamente carpetas autorizadas de solo lectura.

## Desarrollo local

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
CBM_DATA=/tmp/cbm-dev CBM_SOURCES=./sample-data CBM_ALLOW_HTTP=1 uvicorn app.main:app --reload
```

En producción nunca uses `CBM_ALLOW_HTTP=1`. El servidor requiere `rclone` y `restic` instalados en el PATH.

## Próximas funciones pendientes

Agente Linux de solo lectura para descubrir contenedores, capturar Compose de Dokploy y bind mounts; copias PostgreSQL consistentes; protección de volúmenes; renovación OAuth pCloud; exportación/recuperación segura de secretos; políticas de retención verificadas; prueba automática de restauración y recuperación completa de Ubuntu mediante entorno de rescate.
