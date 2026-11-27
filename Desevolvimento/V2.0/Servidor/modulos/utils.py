#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Utilitários compartilhados - RRFS Servidores"""

import os
import subprocess
import logging

logger = logging.getLogger('RRFS.Utils')


def executar_comando(comando, timeout=60):
    """Executa comando shell e retorna resultado"""
    try:
        env = os.environ.copy()
        env['PATH'] = (
            '/usr/local/sbin:/usr/local/bin:'
            '/usr/sbin:/usr/bin:/sbin:/bin'
        )
        r = subprocess.run(
            comando,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
        )
        return {
            'sucesso': r.returncode == 0,
            'saida': r.stdout.strip(),
            'erro': r.stderr.strip(),
            'codigo': r.returncode
        }
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout ({timeout}s): {comando}")
        return {'sucesso': False, 'saida': '', 'erro': 'Timeout', 'codigo': -1}
    except Exception as e:
        logger.error(f"executar_comando: {e}")
        return {'sucesso': False, 'saida': '', 'erro': str(e), 'codigo': -1}


def gerar_ssl(ssl_dir):
    """Gera certificado SSL auto-assinado"""
    try:
        cert = os.path.join(ssl_dir, 'cert.pem')
        key  = os.path.join(ssl_dir, 'key.pem')
        os.makedirs(ssl_dir, exist_ok=True)

        cmd = (
            f'openssl req -x509 -newkey rsa:4096 '
            f'-keyout {key} -out {cert} '
            f'-days 3650 -nodes '
            f'-subj "/CN=RRFS-Servidores/O=RRFS/C=BR" '
            f'-addext "subjectAltName=IP:127.0.0.1,IP:0.0.0.0"'
        )
        r = executar_comando(cmd, timeout=60)
        if r['sucesso']:
            os.chmod(cert, 0o644)
            os.chmod(key,  0o600)
            return True
        logger.error(f"gerar_ssl: {r['erro']}")
        return False
    except Exception as e:
        logger.error(f"gerar_ssl exception: {e}")
        return False
