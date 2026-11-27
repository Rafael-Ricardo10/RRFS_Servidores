#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
instalar_atalho.py - RRFS Servidores - Instalador de Atalho
Cria um atalho de desktop (.desktop) para executar o RRFS Cliente Tox
com o ambiente virtual do distrobox.
"""

import os
import sys
import subprocess
from pathlib import Path

# Caminhos
HOME = Path.home()
APP_DIR = HOME / ".local" / "share" / "RRFS_Servidores"
ENV_DIR = APP_DIR / "env"
VENV_BIN = ENV_DIR / "bin" / "python3"
CLIENTE_SCRIPT = APP_DIR / "cliente_tox.py"
LOGO_PATH = APP_DIR / "static" / "logo.png"

# Diretórios de desktop
DESKTOP_LOCAL = HOME / ".local" / "share" / "applications"
DESKTOP_SYSTEM = Path("/usr/share/applications")

# Conteúdo do arquivo .desktop
DESKTOP_CONTENT = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=RRFS Servidores
Comment=Acesso Remoto via Tox
Exec=distrobox enter debian -- {VENV_BIN} {CLIENTE_SCRIPT}
Icon={LOGO_PATH}
Terminal=false
Categories=System;Network;Utility;
Keywords=tox;remote;access;server;
StartupNotify=true
X-Desktop-File-Install-Version=0.24
"""

def criar_desktop_local():
    """Cria o arquivo .desktop no diretório local do usuário."""
    print("[*] Criando atalho no diretório local do usuário...")

    DESKTOP_LOCAL.mkdir(parents=True, exist_ok=True)
    desktop_file = DESKTOP_LOCAL / "rrfs-servidores.desktop"

    with open(desktop_file, 'w', encoding='utf-8') as f:
        f.write(DESKTOP_CONTENT)

    os.chmod(desktop_file, 0o644)
    print(f"[OK] Atalho criado: {desktop_file}")
    return str(desktop_file)


def criar_desktop_sistema():
    """Tenta criar o arquivo .desktop no diretório de sistema."""
    print("[*] Criando atalho no diretório de sistema...")

    desktop_file = DESKTOP_SYSTEM / "rrfs-servidores.desktop"

    try:
        # Tentar escrever diretamente
        with open(desktop_file, 'w', encoding='utf-8') as f:
            f.write(DESKTOP_CONTENT)
        os.chmod(desktop_file, 0o644)
        print(f"[OK] Atalho criado em sistema: {desktop_file}")
        return str(desktop_file)
    except PermissionError:
        print("[WARN] Sem permissao para escrever em /usr/share/applications")
        print("[INFO] Tentando com sudo...")

        # Criar temporário e usar sudo
        tmp_desktop = Path("/tmp/rrfs-servidores.desktop")
        with open(tmp_desktop, 'w', encoding='utf-8') as f:
            f.write(DESKTOP_CONTENT)

        try:
            resultado = subprocess.run(
                ["sudo", "cp", str(tmp_desktop), str(desktop_file)],
                capture_output=True, text=True, timeout=10
            )
            if resultado.returncode == 0:
                subprocess.run(["sudo", "chmod", "644", str(desktop_file)])
                print(f"[OK] Atalho criado com sudo: {desktop_file}")
                tmp_desktop.unlink()
                return str(desktop_file)
            else:
                print(f"[ERRO] Falha ao copiar: {resultado.stderr}")
                tmp_desktop.unlink()
                return None
        except Exception as e:
            print(f"[ERRO] Falha ao usar sudo: {e}")
            tmp_desktop.unlink()
            return None
    except Exception as e:
        print(f"[ERRO] Falha ao criar atalho de sistema: {e}")
        return None


def criar_script_launcher():
    """Cria um script wrapper para facilitar a execução."""
    print("[*] Criando script launcher...")

    launcher_path = APP_DIR / "executar.sh"
    launcher_content = f"""#!/bin/bash
# RRFS Cliente Tox Launcher
# Executa dentro do distrobox debian

cd "{APP_DIR}"
distrobox enter debian -- {VENV_BIN} {CLIENTE_SCRIPT}
"""

    with open(launcher_path, 'w', encoding='utf-8') as f:
        f.write(launcher_content)

    os.chmod(launcher_path, 0o755)
    print(f"[OK] Script launcher criado: {launcher_path}")
    return str(launcher_path)


def verificar_dependencias():
    """Verifica se as dependências existem."""
    print("[*] Verificando dependencias...")

    erros = []

    if not APP_DIR.exists():
        erros.append(f"Diretorio da app nao existe: {APP_DIR}")

    if not ENV_DIR.exists():
        erros.append(f"Ambiente virtual nao existe: {ENV_DIR}")

    if not VENV_BIN.exists():
        erros.append(f"Python do venv nao encontrado: {VENV_BIN}")

    if not CLIENTE_SCRIPT.exists():
        erros.append(f"Script cliente nao encontrado: {CLIENTE_SCRIPT}")

    if not LOGO_PATH.exists():
        erros.append(f"Logo nao encontrado: {LOGO_PATH}")

    if erros:
        print("\n[ERRO] Problemas encontrados:")
        for erro in erros:
            print(f"  - {erro}")
        return False

    print("[OK] Todas as dependencias verificadas")
    return True


def atualizar_banco_dados_desktop():
    """Atualiza o banco de dados de atalhos do desktop."""
    print("[*] Atualizando banco de dados de atalhos...")

    try:
        resultado = subprocess.run(
            ["update-desktop-database", str(DESKTOP_LOCAL)],
            capture_output=True, text=True, timeout=10
        )
        if resultado.returncode == 0:
            print("[OK] Banco de dados atualizado")
            return True
        else:
            print(f"[WARN] update-desktop-database falhou: {resultado.stderr}")
            return False
    except FileNotFoundError:
        print("[WARN] update-desktop-database nao instalado (opcional)")
        return False
    except Exception as e:
        print(f"[WARN] Erro ao atualizar banco de dados: {e}")
        return False


def instalar():
    """Executa a instalacao completa."""
    print("=" * 60)
    print("RRFS Servidores - Instalador de Atalho")
    print("=" * 60)
    print()

    # Verificar dependências
    if not verificar_dependencias():
        print("\n[ERRO] Nao e possivel prosseguir")
        return False

    print()

    # Criar launcher script
    criar_script_launcher()
    print()

    # Criar atalho local
    desktop_local = criar_desktop_local()
    print()

    # Tentar criar atalho de sistema
    desktop_sistema = criar_desktop_sistema()
    print()

    # Atualizar banco de dados
    atualizar_banco_dados_desktop()
    print()

    # Resumo final
    print("=" * 60)
    print("INSTALACAO CONCLUIDA!")
    print("=" * 60)
    print()
    print("Atalhos criados:")
    print(f"  * Local (usuario): {desktop_local}")
    if desktop_sistema:
        print(f"  * Sistema: {desktop_sistema}")
    else:
        print(f"  * Sistema: NÃO INSTALADO (execute manualmente com sudo se desejar)")
    print()
    print("Opcoes de execucao:")
    print(f"  1. Procure por 'RRFS Servidores' no menu de aplicacoes")
    print(f"  2. Execute: {APP_DIR}/executar.sh")
    print(f"  3. Execute: distrobox enter debian -- {VENV_BIN} {CLIENTE_SCRIPT}")
    print()

    return True


if __name__ == "__main__":
    try:
        sucesso = instalar()
        sys.exit(0 if sucesso else 1)
    except KeyboardInterrupt:
        print("\n[INFO] Instalacao cancelada pelo usuario")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERRO] Falha na instalacao: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
