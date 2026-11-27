#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
instalar_atalho.py - RRFS Servidores - Recria os atalhos (sem root)

Use SOMENTE depois do instalar.sh (que já cria o container Debian no
distrobox e o ambiente virtual). Este script apenas refaz o launcher e
os atalhos do menu/autostart do usuário, apontando para o container.
Não usa sudo e não escreve fora da HOME.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

HOME = Path.home()
APP_DIR = HOME / ".local" / "share" / "RRFS-Servidor"
VENV_PY = APP_DIR / "env" / "bin" / "python3"
CLIENTE = APP_DIR / "cliente_tox.py"
CONF = APP_DIR / "container.conf"
LAUNCHER = APP_DIR / "executar.sh"
ID_APP = "rrfs-servidor"
PORTA = 2100

APPS_DIR = HOME / ".local" / "share" / "applications"
AUTOSTART_DIR = HOME / ".config" / "autostart"
DESKTOP = APPS_DIR / f"{ID_APP}.desktop"
DESKTOP_AUTO = AUTOSTART_DIR / f"{ID_APP}.desktop"


def container():
    try:
        return CONF.read_text(encoding="utf-8").splitlines()[0].strip() or "debian"
    except Exception:
        return "debian"


def verificar():
    erros = []
    if not shutil.which("distrobox"):
        erros.append("distrobox não instalado (rode ./instalar.sh)")
    for p in (APP_DIR, VENV_PY, CLIENTE):
        if not p.exists():
            erros.append(f"Não encontrado: {p} (rode ./instalar.sh)")
    if erros:
        print("[ERRO] Problemas encontrados:")
        for e in erros:
            print("  -", e)
        return False
    return True


def criar_launcher(nome):
    conteudo = f"""#!/usr/bin/env bash
# RRFS Servidores - launcher (executa dentro do distrobox)
APP_DIR="{APP_DIR}"
CONTAINER="{nome}"
PORTA={PORTA}
URL="http://127.0.0.1:$PORTA/"

porta_em_uso() {{
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -q ":$PORTA "
    else
        (exec 3<>/dev/tcp/127.0.0.1/$PORTA) 2>/dev/null
    fi
}}

if porta_em_uso; then
    [ "${{1:-}}" = "--autostart" ] || xdg-open "$URL" >/dev/null 2>&1
    exit 0
fi

mkdir -p "$APP_DIR/dados_tox_cliente"
cd "$APP_DIR" || exit 1
export XDG_RUNTIME_DIR="${{XDG_RUNTIME_DIR:-/run/user/$(id -u)}}"
export DBUS_SESSION_BUS_ADDRESS="${{DBUS_SESSION_BUS_ADDRESS:-unix:path=$XDG_RUNTIME_DIR/bus}}"
export PYSTRAY_BACKEND="${{PYSTRAY_BACKEND:-appindicator}}"

exec distrobox enter "$CONTAINER" -- env \\
    PYSTRAY_BACKEND="${{PYSTRAY_BACKEND:-}}" \\
    "$APP_DIR/env/bin/python3" "$APP_DIR/cliente_tox.py" \\
    >> "$APP_DIR/dados_tox_cliente/launcher.log" 2>&1 </dev/null
"""
    LAUNCHER.write_text(conteudo, encoding="utf-8")
    os.chmod(LAUNCHER, 0o755)
    print(f"[OK] Launcher: {LAUNCHER}")


def criar_desktops():
    APPS_DIR.mkdir(parents=True, exist_ok=True)
    AUTOSTART_DIR.mkdir(parents=True, exist_ok=True)
    base = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=RRFS Servidores
GenericName=Acesso Remoto via Tox
Comment=Acesso remoto a servidores via protocolo Tox (container Debian)
Exec={LAUNCHER}
Icon={ID_APP}
Terminal=false
Categories=System;Network;RemoteAccess;Utility;
Keywords=tox;remoto;acesso;servidor;ssh;rrfs;
StartupNotify=false
"""
    DESKTOP.write_text(base, encoding="utf-8")
    os.chmod(DESKTOP, 0o755)
    print(f"[OK] Atalho: {DESKTOP}")

    auto = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=RRFS Servidores
Comment=Inicia o cliente Tox ao entrar na sessão
Exec={LAUNCHER} --autostart
Icon={ID_APP}
Terminal=false
X-KDE-autostart-after=panel
X-KDE-StartupNotify=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=8
Hidden=false
"""
    DESKTOP_AUTO.write_text(auto, encoding="utf-8")
    os.chmod(DESKTOP_AUTO, 0o644)
    print(f"[OK] Autostart: {DESKTOP_AUTO}")


def atualizar_caches():
    for cmd in (["update-desktop-database", str(APPS_DIR)], ["kbuildsycoca6"], ["kbuildsycoca5"]):
        if shutil.which(cmd[0]):
            subprocess.run(cmd, capture_output=True)
            if cmd[0].startswith("kbuild"):
                break


def main():
    print("=" * 60)
    print("RRFS Servidores - Recriar atalhos (sem root)")
    print("=" * 60)
    if os.geteuid() == 0:
        print("[ERRO] Não execute como root.")
        return 1
    if not verificar():
        return 1
    nome = container()
    print(f"[*] Container: {nome}")
    criar_launcher(nome)
    criar_desktops()
    atualizar_caches()
    print("\nPronto. Procure 'RRFS Servidores' no menu ou rode:", LAUNCHER)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[INFO] Cancelado.")
        sys.exit(1)
