#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Antivírus ClamAV - RRFS Servidores v2.0
Scan inteligente + quarentena + proteção tempo real
Corrigido: tmpfiles, AppArmor, configs ClamAV 1.x
"""

import os
import re
import json
import time
import shutil
import hashlib
import logging
import threading
from datetime import datetime
from pathlib import Path

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Antivirus')


class AntivirusManager:

    def __init__(self, base_dir):
        self.base_dir     = base_dir
        self._cfg_path    = os.path.join(
            base_dir, 'dados', 'av_config.json'
        )
        self._hashes_path = os.path.join(
            base_dir, 'dados', 'av_hashes.json'
        )
        self._q_path      = os.path.join(
            base_dir, 'dados', 'quarentena'
        )
        self._scan_ativo  = False
        self._scan_info   = {}
        self._lock        = threading.Lock()
        self._config      = self._carregar_config()

        os.makedirs(self._q_path, exist_ok=True)
        os.makedirs(
            os.path.dirname(self._cfg_path), exist_ok=True
        )

    # ── config ────────────────────────────────────────────

    def _carregar_config(self):
        try:
            if os.path.exists(self._cfg_path):
                with open(self._cfg_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"av carregar_config: {e}")
        return {
            'instalado':            False,
            'protecao_tempo_real':  False,
            'caminhos_extras':      ['/DATA'],
            'scan_semanal':         True,
            'scan_diario_dirs': [
                '/tmp', '/var/tmp', '/home',
                '/root', '/DATA'
            ],
            'ultimo_scan_completo': '',
            'ultimo_scan_diario':   '',
            'ultimo_update_db':     '',
        }

    def _salvar_config(self):
        try:
            with open(self._cfg_path, 'w') as f:
                json.dump(self._config, f,
                          indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"av salvar_config: {e}")

    # ── status ────────────────────────────────────────────

    def obter_status(self):
        try:
            instalado  = self._clamav_instalado()
            db_info    = self._info_banco_virus()
            quarentena = self.listar_quarentena()

            daemon_ativo    = False
            freshclam_ativo = False
            if instalado:
                r = executar_comando(
                    'systemctl is-active clamav-daemon '
                    '2>/dev/null'
                )
                daemon_ativo = (
                    r['sucesso'] and
                    'active' in r.get('saida', '')
                )
                r2 = executar_comando(
                    'systemctl is-active clamav-freshclam '
                    '2>/dev/null'
                )
                freshclam_ativo = (
                    r2['sucesso'] and
                    'active' in r2.get('saida', '')
                )

            return {
                'instalado':            instalado,
                'daemon_ativo':         daemon_ativo,
                'freshclam_ativo':      freshclam_ativo,
                'protecao_tempo_real':  self._config.get(
                    'protecao_tempo_real', False
                ),
                'versao_clamav':        db_info.get(
                    'versao', '--'
                ),
                'banco_virus':          db_info.get(
                    'banco', '--'
                ),
                'ultima_atualizacao':   db_info.get(
                    'data_atualizacao', '--'
                ),
                'assinaturas':          db_info.get(
                    'assinaturas', 0
                ),
                'quarentena_total':     len(quarentena),
                'scan_ativo':           self._scan_ativo,
                'scan_info':            self._scan_info,
                'caminhos_extras':      self._config.get(
                    'caminhos_extras', []
                ),
                'ultimo_scan_completo': self._config.get(
                    'ultimo_scan_completo', '--'
                ),
                'ultimo_scan_diario':   self._config.get(
                    'ultimo_scan_diario', '--'
                ),
                'ultimo_update_db':     self._config.get(
                    'ultimo_update_db', '--'
                ),
            }
        except Exception as e:
            logger.error(f"av obter_status: {e}")
            return {'instalado': False, 'scan_ativo': False}

    def obter_status_resumido(self):
        try:
            r = executar_comando(
                'systemctl is-active clamav-daemon 2>/dev/null'
            )
            return {
                'instalado':    self._clamav_instalado(),
                'daemon_ativo': (
                    r['sucesso'] and
                    'active' in r.get('saida', '')
                ),
                'scan_ativo':   self._scan_ativo,
                'quarentena':   len(self.listar_quarentena())
            }
        except Exception as e:
            logger.error(f"av status_resumido: {e}")
            return {'instalado': False}

    def _clamav_instalado(self):
        r = executar_comando('which clamscan 2>/dev/null')
        return r['sucesso']

    def _info_banco_virus(self):
        try:
            r = executar_comando(
                'sigtool --info /var/lib/clamav/main.cvd '
                '2>/dev/null || '
                'sigtool --info /var/lib/clamav/main.cld '
                '2>/dev/null',
                timeout=10
            )
            info = {
                'versao': '--', 'banco': '--',
                'assinaturas': 0, 'data_atualizacao': '--'
            }
            if r['sucesso'] and r['saida']:
                for linha in r['saida'].splitlines():
                    l = linha.lower()
                    if 'signatures' in l:
                        m = re.search(r'\d+', linha)
                        if m:
                            info['assinaturas'] = int(m.group())
                    if 'version' in l:
                        m = re.search(r'[\d.]+', linha)
                        if m:
                            info['versao'] = m.group()
                    if 'build time' in l or 'date' in l:
                        info['data_atualizacao'] = \
                            linha.split(':', 1)[-1].strip()

            rv = executar_comando(
                'clamscan --version 2>/dev/null', timeout=5
            )
            if rv['sucesso']:
                info['banco'] = rv['saida'].split('\n')[0]

            return info
        except Exception as e:
            logger.error(f"av _info_banco: {e}")
            return {}

    # ══════════════════════════════════════════════════════
    # INSTALAR
    # ══════════════════════════════════════════════════════

    def instalar(self):
        try:
            # 1. instalar pacotes
            r = executar_comando(
                'apt-get install -y '
                'clamav clamav-daemon clamav-freshclam '
                'clamav-base',
                timeout=300
            )
            if not r['sucesso']:
                return {
                    'sucesso': False,
                    'erro': 'Falha ao instalar ClamAV'
                }

            # 2. parar serviços
            for svc in ['clamav-freshclam', 'clamav-daemon']:
                executar_comando(
                    f'systemctl stop {svc} 2>/dev/null',
                    timeout=15
                )
            time.sleep(2)

            # 3. configurar tmpfiles (CRÍTICO para reboot)
            self._configurar_tmpfiles()

            # 4. criar diretórios agora
            self._criar_diretorios()

            # 5. permissões
            self._corrigir_permissoes_clamav()

            # 6. AppArmor
            self._ajustar_apparmor_clamav()

            # 7. override systemd (CRÍTICO para reboot)
            self._configurar_systemd_overrides()

            # 8. freshclam.conf corrigido
            self._configurar_freshclam()

            # 9. clamd.conf corrigido
            self._configurar_daemon()

            # 10. recarregar systemd
            executar_comando(
                'systemctl daemon-reload', timeout=15
            )

            # 11. atualizar banco
            r2 = self.atualizar_banco()

            # 12. iniciar serviços
            for svc in ['clamav-daemon', 'clamav-freshclam']:
                executar_comando(
                    f'systemctl enable {svc}', timeout=10
                )
                executar_comando(
                    f'systemctl start {svc}', timeout=30
                )

            self._config['instalado'] = True
            self._salvar_config()

            # 13. cron
            self._configurar_cron()

            return {
                'sucesso': True,
                'mensagem': 'ClamAV instalado e configurado!',
                'banco': r2.get('mensagem', '')
            }
        except Exception as e:
            logger.error(f"av instalar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # CONFIGURAÇÕES DO SISTEMA (boot-safe)
    # ══════════════════════════════════════════════════════

    def _configurar_tmpfiles(self):
        """
        Configura systemd-tmpfiles para criar /run/clamav
        automaticamente em cada boot.

        /run/ é tmpfs - é LIMPO em cada reboot.
        tmpfiles.d garante que o diretório seja
        recriado antes dos serviços iniciarem.
        """
        try:
            conteudo = (
                '# ClamAV runtime directory - RRFS\n'
                '# Recriado automaticamente no boot\n'
                'd /run/clamav 0755 clamav clamav -\n'
            )
            with open(
                '/usr/lib/tmpfiles.d/clamav.conf', 'w'
            ) as f:
                f.write(conteudo)

            # aplicar imediatamente
            executar_comando(
                'systemd-tmpfiles --create '
                '/usr/lib/tmpfiles.d/clamav.conf',
                timeout=10
            )
        except Exception as e:
            logger.error(f"av _configurar_tmpfiles: {e}")

    def _configurar_systemd_overrides(self):
        """
        Override dos serviços ClamAV para garantir que
        /run/clamav existe antes de iniciar.

        RuntimeDirectory=clamav faz o systemd criar
        /run/clamav automaticamente antes de cada start.
        """
        try:
            overrides = {
                '/etc/systemd/system/'
                'clamav-freshclam.service.d/rrfs.conf': (
                    '[Service]\n'
                    'RuntimeDirectory=clamav\n'
                    'RuntimeDirectoryMode=0755\n'
                ),
                '/etc/systemd/system/'
                'clamav-daemon.service.d/rrfs.conf': (
                    '[Service]\n'
                    'RuntimeDirectory=clamav\n'
                    'RuntimeDirectoryMode=0755\n'
                ),
            }

            for path, conteudo in overrides.items():
                os.makedirs(
                    os.path.dirname(path), exist_ok=True
                )
                with open(path, 'w') as f:
                    f.write(conteudo)

        except Exception as e:
            logger.error(
                f"av _configurar_systemd_overrides: {e}"
            )

    def _criar_diretorios(self):
        """Cria diretórios necessários agora"""
        dirs = [
            '/run/clamav',
            '/var/log/clamav',
            '/var/lib/clamav',
            self._q_path,
        ]
        for d in dirs:
            try:
                os.makedirs(d, exist_ok=True)
            except Exception as e:
                logger.error(f"av criar dir {d}: {e}")

    def _corrigir_permissoes_clamav(self):
        try:
            cmds = [
                'chown clamav:clamav /run/clamav',
                'chmod 755 /run/clamav',
                'chown -R clamav:clamav /var/log/clamav',
                'chmod 755 /var/log/clamav',
                'chown -R clamav:clamav /var/lib/clamav',
                'chmod 755 /var/lib/clamav',
            ]
            for c in cmds:
                executar_comando(c, timeout=10)
        except Exception as e:
            logger.error(f"av _corrigir_permissoes: {e}")

    def _ajustar_apparmor_clamav(self):
        """
        Perfis locais do AppArmor para ClamAV.
        Adiciona permissões para quarentena e /DATA.
        """
        try:
            os.makedirs(
                '/etc/apparmor.d/local', exist_ok=True
            )

            perfis = {
                '/etc/apparmor.d/local/usr.bin.freshclam': (
                    '# RRFS - permissões extras freshclam\n'
                    '/run/clamav/ rw,\n'
                    '/run/clamav/** rw,\n'
                ),
                '/etc/apparmor.d/local/usr.sbin.clamd': (
                    '# RRFS - permissões extras clamd\n'
                    '/run/clamav/ rw,\n'
                    '/run/clamav/** rw,\n'
                    f'{self._q_path}/ rw,\n'
                    f'{self._q_path}/** rw,\n'
                    '/DATA/ r,\n'
                    '/DATA/** r,\n'
                ),
            }

            for arq, conteudo in perfis.items():
                with open(arq, 'w') as f:
                    f.write(conteudo)

            for perfil in [
                '/etc/apparmor.d/usr.bin.freshclam',
                '/etc/apparmor.d/usr.sbin.clamd',
            ]:
                if os.path.exists(perfil):
                    executar_comando(
                        f'apparmor_parser -r "{perfil}" '
                        f'2>/dev/null',
                        timeout=15
                    )

            time.sleep(1)

        except Exception as e:
            logger.error(f"av _ajustar_apparmor: {e}")

    # ── configs ClamAV corrigidas ─────────────────────────

    def _configurar_freshclam(self):
        """
        Correções ClamAV 1.x:
        - DataBasePath → DatabaseDirectory
        - SafeBrowsing removido (descontinuado)
        - PidFile → /run/clamav/ (não /var/run/)
        """
        try:
            conf = """\
# RRFS - ClamAV Freshclam
# Gerado automaticamente - nao edite manualmente
DatabaseOwner clamav
UpdateLogFile /var/log/clamav/freshclam.log
LogVerbose false
LogSyslog false
LogFacility LOG_LOCAL6
LogFileMaxSize 2M
LogTime true
PidFile /run/clamav/freshclam.pid
DatabaseDirectory /var/lib/clamav
DatabaseMirror database.clamav.net
DatabaseMirror db.br.clamav.net
Checks 24
ConnectTimeout 30
ReceiveTimeout 300
Bytecode true
"""
            with open(
                '/etc/clamav/freshclam.conf', 'w'
            ) as f:
                f.write(conf)
            os.chmod('/etc/clamav/freshclam.conf', 0o644)

        except Exception as e:
            logger.error(f"av _configurar_freshclam: {e}")

    def _configurar_daemon(self):
        """
        Correções:
        - LocalSocket → /run/clamav/ (não /var/run/)
        - PidFile → /run/clamav/
        """
        try:
            conf = """\
# RRFS - ClamAV Daemon
# Gerado automaticamente - nao edite manualmente
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 666
FixStaleSocket true
TCPSocket 3310
TCPAddr 127.0.0.1
MaxConnectionQueueLength 30
LogSyslog false
LogFile /var/log/clamav/clamav.log
LogFileMaxSize 2M
LogTime true
LogVerbose false
PidFile /run/clamav/clamd.pid
DatabaseDirectory /var/lib/clamav
SelfCheck 600
User clamav
AllowSupplementaryGroups true
ScanPE true
ScanELF true
ScanOLE2 true
ScanPDF true
ScanSWF true
ScanHTML true
ScanMail true
ScanArchive true
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 10
MaxFiles 15000
MaxEmbeddedPE 10M
MaxHTMLNormalize 10M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
"""
            with open('/etc/clamav/clamd.conf', 'w') as f:
                f.write(conf)
            os.chmod('/etc/clamav/clamd.conf', 0o644)

        except Exception as e:
            logger.error(f"av _configurar_daemon: {e}")

    # ══════════════════════════════════════════════════════
    # ATUALIZAR BANCO
    # ══════════════════════════════════════════════════════

    def atualizar_banco(self):
        try:
            executar_comando(
                'systemctl stop clamav-freshclam 2>/dev/null',
                timeout=10
            )
            time.sleep(2)

            # garantir que /run/clamav existe
            self._criar_diretorios()
            self._corrigir_permissoes_clamav()

            r = executar_comando(
                'freshclam --no-warnings 2>/dev/null',
                timeout=300
            )

            executar_comando(
                'systemctl start clamav-freshclam',
                timeout=15
            )

            self._config['ultimo_update_db'] = \
                datetime.now().strftime('%d/%m/%Y %H:%M')
            self._salvar_config()

            saida = r.get('saida', '').lower()
            if r['sucesso'] or 'up to date' in saida:
                return {
                    'sucesso': True,
                    'mensagem': 'Banco de vírus atualizado!'
                }
            return {
                'sucesso': True,
                'mensagem': 'Banco verificado.'
            }
        except Exception as e:
            logger.error(f"av atualizar_banco: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # SCAN
    # ══════════════════════════════════════════════════════

    def iniciar_scan(self, caminho='/', tipo='completo'):
        if self._scan_ativo:
            return {
                'sucesso': False,
                'erro': 'Scan já em andamento'
            }

        def _rodar():
            self._scan_ativo = True
            self._scan_info  = {
                'tipo':                 tipo,
                'caminho':              caminho,
                'inicio':               datetime.now().isoformat(),
                'progresso':            'iniciando...',
                'arquivos_verificados': 0,
                'ameacas_encontradas':  0,
            }
            try:
                hashes = self._carregar_hashes()
                self._executar_scan(caminho, tipo, hashes)
            finally:
                self._scan_ativo = False
                chave = (
                    'ultimo_scan_completo'
                    if tipo == 'completo'
                    else 'ultimo_scan_diario'
                )
                self._config[chave] = \
                    datetime.now().strftime('%d/%m/%Y %H:%M')
                self._salvar_config()

        threading.Thread(target=_rodar, daemon=True).start()
        return {
            'sucesso': True,
            'mensagem': f'Scan {tipo} iniciado em {caminho}'
        }

    def _executar_scan(self, caminho, tipo, hashes):
        try:
            self._scan_info['progresso'] = 'escaneando...'
            ameacas      = 0
            novos_hashes = {}

            r = executar_comando(
                f'find {caminho} -type f '
                f'-not -path "*/proc/*" '
                f'-not -path "*/sys/*" '
                f'-not -path "*/dev/*" '
                f'-not -path "*{self._q_path}*" '
                f'2>/dev/null',
                timeout=120
            )
            if not r['sucesso']:
                return

            arquivos = [
                a for a in r['saida'].splitlines()
                if a.strip()
            ]
            total = len(arquivos)

            for i, arq in enumerate(arquivos):
                if not self._scan_ativo:
                    break

                self._scan_info['progresso'] = f'{i+1}/{total}'
                self._scan_info['arquivos_verificados'] = i + 1

                try:
                    stat   = os.stat(arq)
                    chave  = arq
                    h_info = hashes.get(chave, {})
                    mtime  = stat.st_mtime
                    size   = stat.st_size

                    if (h_info.get('mtime') == mtime and
                            h_info.get('size') == size):
                        novos_hashes[chave] = h_info
                        continue

                    rs = executar_comando(
                        f'clamscan --no-summary '
                        f'--quiet "{arq}" 2>/dev/null',
                        timeout=30
                    )

                    novos_hashes[chave] = {
                        'mtime':   mtime,
                        'size':    size,
                        'ok':      rs['sucesso'],
                        'scanned': datetime.now().isoformat()
                    }

                    saida_rs = (
                        rs.get('saida', '') +
                        rs.get('erro', '')
                    )
                    if not rs['sucesso'] or \
                            'FOUND' in saida_rs:
                        virus = self._extrair_virus(saida_rs)
                        ameacas += 1
                        self._scan_info[
                            'ameacas_encontradas'
                        ] = ameacas
                        self._mover_quarentena(arq, virus)
                        novos_hashes[chave]['virus'] = virus

                except (PermissionError, FileNotFoundError):
                    pass
                except Exception as e:
                    logger.error(f"av scan {arq}: {e}")

            self._salvar_hashes(novos_hashes)
            self._scan_info['progresso'] = 'concluído'
            self._scan_info['fim'] = datetime.now().isoformat()
            self._scan_info['ameacas_encontradas'] = ameacas

        except Exception as e:
            logger.error(f"av _executar_scan: {e}")
            self._scan_info['progresso'] = f'erro: {e}'

    def _extrair_virus(self, saida):
        m = re.search(r'FOUND\s*$', saida, re.MULTILINE)
        if m:
            linha = (
                saida[:m.start()].strip().split('\n')[-1]
            )
            partes = linha.split(':')
            if len(partes) >= 2:
                return partes[-1].strip().replace(
                    ' FOUND', ''
                )
        return 'Vírus desconhecido'

    def status_scan(self):
        return {'ativo': self._scan_ativo, **self._scan_info}

    # ══════════════════════════════════════════════════════
    # QUARENTENA
    # ══════════════════════════════════════════════════════

    def _mover_quarentena(self, arquivo_orig, virus_nome):
        try:
            ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
            rid = hashlib.md5(
                f"{arquivo_orig}{ts}".encode()
            ).hexdigest()[:8]
            nome_q = (
                f"{rid}_{os.path.basename(arquivo_orig)}"
            )
            dest = os.path.join(self._q_path, nome_q)
            shutil.move(arquivo_orig, dest)
            os.chmod(dest, 0o600)
            meta = self._carregar_quarentena_meta()
            meta.append({
                'id':           rid,
                'arquivo_orig': arquivo_orig,
                'arquivo_q':    dest,
                'virus':        virus_nome,
                'data':         datetime.now().isoformat(),
                'tamanho':      os.path.getsize(dest)
            })
            self._salvar_quarentena_meta(meta)
        except Exception as e:
            logger.error(f"av _mover_quarentena: {e}")

    def listar_quarentena(self):
        return self._carregar_quarentena_meta()

    def restaurar_quarentena(self, rid):
        try:
            meta = self._carregar_quarentena_meta()
            for i, item in enumerate(meta):
                if item.get('id') == rid:
                    orig  = item['arquivo_orig']
                    arq_q = item['arquivo_q']
                    if not os.path.exists(arq_q):
                        return {
                            'sucesso': False,
                            'erro': 'Arquivo não encontrado'
                        }
                    os.makedirs(
                        os.path.dirname(orig), exist_ok=True
                    )
                    shutil.move(arq_q, orig)
                    meta.pop(i)
                    self._salvar_quarentena_meta(meta)
                    h = self._carregar_hashes()
                    if orig in h:
                        h[orig]['falso_positivo'] = True
                    self._salvar_hashes(h)
                    return {
                        'sucesso': True,
                        'mensagem': f'Restaurado: {orig}'
                    }
            return {
                'sucesso': False, 'erro': 'Não encontrado'
            }
        except Exception as e:
            logger.error(f"av restaurar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_quarentena(self, rid):
        try:
            meta = self._carregar_quarentena_meta()
            for i, item in enumerate(meta):
                if item.get('id') == rid:
                    arq_q = item['arquivo_q']
                    if os.path.exists(arq_q):
                        os.remove(arq_q)
                    meta.pop(i)
                    self._salvar_quarentena_meta(meta)
                    return {
                        'sucesso': True,
                        'mensagem': 'Removido permanentemente'
                    }
            return {
                'sucesso': False, 'erro': 'Não encontrado'
            }
        except Exception as e:
            logger.error(f"av remover_quarentena: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _carregar_quarentena_meta(self):
        path = os.path.join(
            self.base_dir, 'dados', 'quarentena_meta.json'
        )
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"av carregar_q_meta: {e}")
        return []

    def _salvar_quarentena_meta(self, meta):
        path = os.path.join(
            self.base_dir, 'dados', 'quarentena_meta.json'
        )
        try:
            with open(path, 'w') as f:
                json.dump(meta, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"av salvar_q_meta: {e}")

    # ── hashes ────────────────────────────────────────────

    def _carregar_hashes(self):
        try:
            if os.path.exists(self._hashes_path):
                with open(self._hashes_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"av carregar_hashes: {e}")
        return {}

    def _salvar_hashes(self, hashes):
        try:
            with open(self._hashes_path, 'w') as f:
                json.dump(hashes, f, ensure_ascii=False)
        except Exception as e:
            logger.error(f"av salvar_hashes: {e}")

    # ── proteção tempo real ───────────────────────────────

    def configurar_protecao_tempo_real(self, ativo):
        try:
            if ativo:
                executar_comando(
                    'systemctl enable clamav-daemon',
                    timeout=10
                )
                r = executar_comando(
                    'systemctl start clamav-daemon',
                    timeout=30
                )
                if not r['sucesso']:
                    return {
                        'sucesso': False,
                        'erro': 'Falha ao iniciar daemon'
                    }
            else:
                executar_comando(
                    'systemctl stop clamav-daemon',
                    timeout=10
                )
                executar_comando(
                    'systemctl disable clamav-daemon',
                    timeout=10
                )
            self._config['protecao_tempo_real'] = ativo
            self._salvar_config()
            estado = 'ativada' if ativo else 'desativada'
            return {
                'sucesso': True,
                'mensagem': f'Proteção tempo real {estado}.'
            }
        except Exception as e:
            logger.error(f"av protecao_tempo_real: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── caminhos extras ───────────────────────────────────

    def gerenciar_caminho(self, acao, caminho):
        try:
            caminhos = self._config.get(
                'caminhos_extras', []
            )
            if acao == 'adicionar':
                if not os.path.exists(caminho):
                    return {
                        'sucesso': False,
                        'erro': f'Não existe: {caminho}'
                    }
                if caminho not in caminhos:
                    caminhos.append(caminho)
                    self._config['caminhos_extras'] = caminhos
                    self._salvar_config()
                return {
                    'sucesso': True,
                    'mensagem': f'Adicionado: {caminho}'
                }
            elif acao == 'remover':
                if caminho in caminhos:
                    caminhos.remove(caminho)
                    self._config['caminhos_extras'] = caminhos
                    self._salvar_config()
                return {
                    'sucesso': True,
                    'mensagem': f'Removido: {caminho}'
                }
            return {
                'sucesso': False, 'erro': 'Ação inválida'
            }
        except Exception as e:
            logger.error(f"av gerenciar_caminho: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── cron ──────────────────────────────────────────────

    def _configurar_cron(self):
        try:
            q = self._q_path
            cron = (
                '# RRFS Servidores - ClamAV\n'
                '# Scan diário dirs estratégicos (2h)\n'
                f'0 2 * * * root clamscan -r --quiet '
                f'--move={q} '
                f'/tmp /var/tmp /root /DATA '
                f'>> /var/log/clamav/scan_diario.log 2>&1\n'
                '# Scan completo semanal (dom 3h)\n'
                f'0 3 * * 0 root clamscan -r --quiet '
                f'--move={q} '
                f'/ --exclude-dir=/proc --exclude-dir=/sys '
                f'--exclude-dir=/dev '
                f'>> /var/log/clamav/scan_semanal.log 2>&1\n'
                '# Atualizar banco (6h)\n'
                '0 6 * * * root freshclam --quiet '
                '>> /var/log/clamav/freshclam_cron.log 2>&1\n'
            )
            with open('/etc/cron.d/rrfs-clamav', 'w') as f:
                f.write(cron)
            os.chmod('/etc/cron.d/rrfs-clamav', 0o644)
        except Exception as e:
            logger.error(f"av _configurar_cron: {e}")
