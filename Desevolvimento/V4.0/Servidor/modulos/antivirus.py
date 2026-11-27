#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Antivírus ClamAV - RRFS Servidores v2.1

v2.1 (correções):
  - GRAVE: o scan antigo tratava QUALQUER falha do clamscan (timeout de
    30s, erro de leitura, banco não carregado) como "vírus
    desconhecido" e MOVIA o arquivo para a quarentena - podendo
    mover arquivos do sistema. Agora só vai para a quarentena o que o
    ClamAV marca como FOUND; erros são contados à parte.
  - Desempenho: antes rodava UM clamscan por arquivo (carrega o banco
    inteiro a cada arquivo: minutos por arquivo num Raspberry/SBC).
    Agora varre em lotes (clamdscan --fdpass se o daemon estiver ativo,
    senão clamscan -f), sem shell (sem injeção por caminho/nome de
    arquivo).
  - Cache de arquivos limpos é invalidado quando o banco de vírus muda
    (antes um arquivo "limpo" nunca era reavaliado).
  - 'inactive' contém 'active': checagem de serviço agora é exata.
  - systemd: RuntimeDirectoryPreserve=yes (dois serviços dividiam
    /run/clamav e um apagava o diretório do outro ao parar).
  - clamd.conf: removidas opções redundantes/obsoletas (ScanSWF etc.),
    socket 660, sem TCP, ExcludePath para /proc,/sys,/dev,/run,docker
    e quarentena.
  - Cron agora usa um script (rrfs-clamscan.sh) com flock, daemon se
    disponível, e exclui quarentena/docker; arquivos movidos pelo cron
    aparecem na lista de quarentena.
  - Banco: soma main+daily+bytecode, recarrega o clamd após atualizar,
    erros do freshclam são informados; instalação sem internet não
    tenta subir o clamd sem banco.
  - Novo: cancelar_scan(); caminhos validados.
  - Observação: "proteção em tempo real" aqui = daemon clamd ativo
    (varreduras mais rápidas). Não há monitoramento on-access.
"""

import os
import re
import stat
import json
import time
import uuid
import shlex
import shutil
import logging
import tempfile
import threading
import subprocess
from datetime import datetime

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Antivirus')

DB_DIR = '/var/lib/clamav'
SCRIPT_SCAN = '/usr/local/bin/rrfs-clamscan.sh'
EXCLUIR_SEMPRE = ('/proc', '/sys', '/dev', '/run', '/var/lib/docker')
TAM_MAX_ARQUIVO = 400 * 1024 * 1024
TAM_LOTE_DAEMON = 500
TAM_LOTE_CLAMSCAN = 3000
MAX_ENTRADAS_CACHE = 300000
MAX_FALHAS_SEGUIDAS = 3

_ENV = {
    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
}


class AntivirusManager:

    PADRAO = {
        'instalado':            False,
        'protecao_tempo_real':  False,
        'caminhos_extras':      ['/DATA'],
        'scan_semanal':         True,
        'scan_diario_dirs':     ['/tmp', '/var/tmp', '/home',
                                 '/root', '/DATA'],
        'ultimo_scan_completo': '',
        'ultimo_scan_diario':   '',
        'ultimo_update_db':     '',
        'ignorar':              [],
    }

    def __init__(self, base_dir):
        self.base_dir     = base_dir
        self._cfg_path    = os.path.join(base_dir, 'dados',
                                         'av_config.json')
        self._hashes_path = os.path.join(base_dir, 'dados',
                                         'av_hashes.json')
        self._q_meta_path = os.path.join(base_dir, 'dados',
                                         'quarentena_meta.json')
        self._q_path      = os.path.join(base_dir, 'dados', 'quarentena')
        self._scan_ativo  = False
        self._cancelar    = False
        self._scan_info   = {}
        self._lock        = threading.RLock()
        self._info_cache  = {'stamp': None, 'info': None}

        os.makedirs(os.path.dirname(self._cfg_path), exist_ok=True)
        os.makedirs(self._q_path, mode=0o700, exist_ok=True)
        self._config = self._carregar_config()

    # ── persistência ──────────────────────────────────────

    def _ler_json(self, path, padrao):
        try:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"av ler {path}: {e}")
        return padrao

    def _escrever_json(self, path, dados, indent=2):
        try:
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(dados, f, indent=indent, ensure_ascii=False)
            os.replace(tmp, path)
        except Exception as e:
            logger.error(f"av escrever {path}: {e}")

    def _carregar_config(self):
        cfg = json.loads(json.dumps(self.PADRAO))
        dados = self._ler_json(self._cfg_path, {})
        if isinstance(dados, dict):
            cfg.update(dados)
        return cfg

    def _salvar_config(self):
        with self._lock:
            self._escrever_json(self._cfg_path, self._config)

    # ── helpers ───────────────────────────────────────────

    def _servico_ativo(self, nome):
        r = executar_comando(f'systemctl is-active {nome} 2>/dev/null',
                             timeout=10)
        return r.get('saida', '').strip() == 'active'

    def _daemon_ativo(self):
        return self._servico_ativo('clamav-daemon')

    def _clamav_instalado(self):
        return executar_comando('which clamscan 2>/dev/null')['sucesso']

    def _arquivos_banco(self):
        achados = []
        for base in ('main', 'daily', 'bytecode'):
            for ext in ('cvd', 'cld'):
                c = os.path.join(DB_DIR, f'{base}.{ext}')
                if os.path.exists(c):
                    achados.append((base, c))
                    break
        return achados

    def _tem_banco(self):
        return len(self._arquivos_banco()) > 0

    def _db_stamp(self):
        try:
            return '|'.join(f'{os.path.basename(c)}:'
                            f'{int(os.path.getmtime(c))}'
                            for _, c in self._arquivos_banco())
        except Exception:
            return ''

    # ── status ────────────────────────────────────────────

    def obter_status(self):
        try:
            instalado  = self._clamav_instalado()
            db_info    = self._info_banco_virus() if instalado else {}
            quarentena = self.listar_quarentena()

            daemon_ativo = freshclam_ativo = False
            if instalado:
                daemon_ativo    = self._daemon_ativo()
                freshclam_ativo = self._servico_ativo('clamav-freshclam')

            return {
                'instalado':            instalado,
                'daemon_ativo':         daemon_ativo,
                'freshclam_ativo':      freshclam_ativo,
                'protecao_tempo_real':  self._config.get(
                    'protecao_tempo_real', False),
                'versao_clamav':        db_info.get('versao', '--'),
                'banco_virus':          db_info.get('banco', '--'),
                'ultima_atualizacao':   db_info.get(
                    'data_atualizacao', '--'),
                'assinaturas':          db_info.get('assinaturas', 0),
                'quarentena_total':     len(quarentena),
                'scan_ativo':           self._scan_ativo,
                'scan_info':            self._scan_info,
                'caminhos_extras':      self._config.get(
                    'caminhos_extras', []),
                'ultimo_scan_completo': self._config.get(
                    'ultimo_scan_completo', '--'),
                'ultimo_scan_diario':   self._config.get(
                    'ultimo_scan_diario', '--'),
                'ultimo_update_db':     self._config.get(
                    'ultimo_update_db', '--'),
            }
        except Exception as e:
            logger.error(f"av obter_status: {e}")
            return {'instalado': False, 'scan_ativo': False}

    def obter_status_resumido(self):
        try:
            return {
                'instalado':    self._clamav_instalado(),
                'daemon_ativo': self._daemon_ativo(),
                'scan_ativo':   self._scan_ativo,
                'quarentena':   len(self.listar_quarentena()),
            }
        except Exception as e:
            logger.error(f"av status_resumido: {e}")
            return {'instalado': False}

    def _info_banco_virus(self):
        """Soma main+daily+bytecode. Resultado em cache até o banco
        mudar (sigtool --info lê o arquivo inteiro: lento em SBC)."""
        stamp = self._db_stamp()
        if (self._info_cache['stamp'] == stamp and
                self._info_cache['info'] is not None):
            return self._info_cache['info']
        info = {'versao': '--', 'banco': '--',
                'assinaturas': 0, 'data_atualizacao': '--'}
        try:
            total = 0
            versoes = {}
            for base, arq in self._arquivos_banco():
                r = executar_comando(
                    f'sigtool --info {shlex.quote(arq)} 2>/dev/null',
                    timeout=60
                )
                if not r['sucesso']:
                    continue
                for linha in r['saida'].splitlines():
                    k, _, v = linha.partition(':')
                    k, v = k.strip().lower(), v.strip()
                    if k == 'signatures' and v.isdigit():
                        total += int(v)
                    elif k == 'version':
                        versoes[base] = v
                    elif k == 'build time' and base == 'daily':
                        info['data_atualizacao'] = v
            info['assinaturas'] = total
            info['versao'] = (versoes.get('daily') or
                              versoes.get('main') or '--')
            rv = executar_comando('clamscan --version 2>/dev/null',
                                  timeout=10)
            if rv['sucesso']:
                info['banco'] = rv['saida'].split('\n')[0]
        except Exception as e:
            logger.error(f"av _info_banco: {e}")
        self._info_cache = {'stamp': stamp, 'info': info}
        return info

    # ══════════════════════════════════════════════════════
    # INSTALAR
    # ══════════════════════════════════════════════════════

    def instalar(self):
        try:
            r = executar_comando(
                'DEBIAN_FRONTEND=noninteractive apt-get install -y '
                'clamav clamav-daemon clamav-freshclam clamav-base',
                timeout=600
            )
            if not r['sucesso']:
                return {'sucesso': False,
                        'erro': 'Falha ao instalar ClamAV: '
                                + (r.get('erro') or '')[-200:]}

            for svc in ('clamav-freshclam', 'clamav-daemon'):
                executar_comando(f'systemctl stop {svc} 2>/dev/null',
                                 timeout=30)
            time.sleep(2)

            self._configurar_tmpfiles()
            self._criar_diretorios()
            self._corrigir_permissoes_clamav()
            self._ajustar_apparmor_clamav()
            self._configurar_systemd_overrides()
            self._configurar_freshclam()
            self._configurar_daemon()
            executar_comando('systemctl daemon-reload', timeout=15)

            r2 = self.atualizar_banco()
            tem_banco = self._tem_banco()

            for svc in ('clamav-daemon', 'clamav-freshclam'):
                executar_comando(f'systemctl enable {svc}', timeout=15)
            if tem_banco:
                executar_comando('systemctl start clamav-freshclam',
                                 timeout=60)
                executar_comando('systemctl start clamav-daemon',
                                 timeout=240)

            self._config['instalado'] = True
            self._salvar_config()
            self._configurar_cron()

            if not tem_banco:
                return {
                    'sucesso': True,
                    'mensagem': ('ClamAV instalado, mas o banco de '
                                 'vírus não foi baixado (sem internet?). '
                                 'Use "Atualizar banco" depois.'),
                    'banco': r2.get('erro', '')
                }
            return {'sucesso': True,
                    'mensagem': 'ClamAV instalado e configurado!',
                    'banco': r2.get('mensagem', '')}
        except Exception as e:
            logger.error(f"av instalar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # CONFIGURAÇÕES DO SISTEMA (boot-safe)
    # ══════════════════════════════════════════════════════

    def _configurar_tmpfiles(self):
        """/run é tmpfs: recria /run/clamav a cada boot."""
        try:
            with open('/usr/lib/tmpfiles.d/clamav.conf', 'w') as f:
                f.write('# ClamAV runtime directory - RRFS\n'
                        'd /run/clamav 0755 clamav clamav -\n')
            executar_comando(
                'systemd-tmpfiles --create '
                '/usr/lib/tmpfiles.d/clamav.conf', timeout=10)
        except Exception as e:
            logger.error(f"av _configurar_tmpfiles: {e}")

    def _configurar_systemd_overrides(self):
        """RuntimeDirectory + Preserve: os dois serviços compartilham
        /run/clamav; sem Preserve, parar um apagava o diretório do
        outro."""
        try:
            conteudo = ('[Service]\n'
                        'RuntimeDirectory=clamav\n'
                        'RuntimeDirectoryMode=0755\n'
                        'RuntimeDirectoryPreserve=yes\n')
            for svc in ('clamav-freshclam', 'clamav-daemon'):
                d = f'/etc/systemd/system/{svc}.service.d'
                os.makedirs(d, exist_ok=True)
                with open(f'{d}/rrfs.conf', 'w') as f:
                    f.write(conteudo)
        except Exception as e:
            logger.error(f"av _configurar_systemd_overrides: {e}")

    def _criar_diretorios(self):
        for d in ('/run/clamav', '/var/log/clamav', DB_DIR,
                  self._q_path):
            try:
                os.makedirs(d, exist_ok=True)
            except Exception as e:
                logger.error(f"av criar dir {d}: {e}")

    def _corrigir_permissoes_clamav(self):
        try:
            for c in ('chown clamav:clamav /run/clamav',
                      'chmod 755 /run/clamav',
                      'chown -R clamav:clamav /var/log/clamav',
                      'chmod 755 /var/log/clamav',
                      'chown -R clamav:clamav /var/lib/clamav',
                      'chmod 755 /var/lib/clamav'):
                executar_comando(c, timeout=15)
        except Exception as e:
            logger.error(f"av _corrigir_permissoes: {e}")

    def _ajustar_apparmor_clamav(self):
        """Perfis locais do AppArmor (só se o AppArmor existir)."""
        try:
            if not os.path.isdir('/etc/apparmor.d'):
                return
            os.makedirs('/etc/apparmor.d/local', exist_ok=True)
            q = self._q_path
            perfis = {
                '/etc/apparmor.d/local/usr.bin.freshclam': (
                    '# RRFS - permissões extras freshclam\n'
                    '/run/clamav/ rw,\n/run/clamav/** rw,\n'),
                '/etc/apparmor.d/local/usr.sbin.clamd': (
                    '# RRFS - permissões extras clamd\n'
                    '/run/clamav/ rw,\n/run/clamav/** rw,\n'
                    f'{q}/ rw,\n{q}/** rw,\n'
                    '/DATA/ r,\n/DATA/** r,\n'),
            }
            for arq, conteudo in perfis.items():
                with open(arq, 'w') as f:
                    f.write(conteudo)
            for perfil in ('/etc/apparmor.d/usr.bin.freshclam',
                           '/etc/apparmor.d/usr.sbin.clamd'):
                if os.path.exists(perfil):
                    executar_comando(
                        f'apparmor_parser -r {shlex.quote(perfil)} '
                        f'2>/dev/null', timeout=20)
            time.sleep(1)
        except Exception as e:
            logger.error(f"av _ajustar_apparmor: {e}")

    def _configurar_freshclam(self):
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
DatabaseMirror db.br.clamav.net
DatabaseMirror database.clamav.net
Checks 24
ConnectTimeout 30
ReceiveTimeout 300
Bytecode true
"""
            with open('/etc/clamav/freshclam.conf', 'w') as f:
                f.write(conf)
            os.chmod('/etc/clamav/freshclam.conf', 0o644)
        except Exception as e:
            logger.error(f"av _configurar_freshclam: {e}")

    def _configurar_daemon(self):
        """clamd.conf enxuto (opções de scan já são 'yes' por padrão;
        removidas as obsoletas, ex.: ScanSWF). Socket 660, sem TCP."""
        try:
            q = re.escape(self._q_path)
            conf = f"""\
# RRFS - ClamAV Daemon
# Gerado automaticamente - nao edite manualmente
LocalSocket /run/clamav/clamd.ctl
LocalSocketGroup clamav
LocalSocketMode 660
FixStaleSocket true
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
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 10
MaxFiles 15000
ExcludePath ^/proc/
ExcludePath ^/sys/
ExcludePath ^/dev/
ExcludePath ^/run/
ExcludePath ^/var/lib/docker/
ExcludePath ^{q}/
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
                timeout=30)
            time.sleep(2)
            self._criar_diretorios()
            self._corrigir_permissoes_clamav()

            r = executar_comando('freshclam --no-warnings', timeout=900)
            saida = (r.get('saida', '') + ' ' +
                     r.get('erro', '')).lower()
            atualizado = ('up-to-date' in saida or
                          'up to date' in saida or
                          'updated' in saida)
            ok = r['sucesso'] or atualizado

            executar_comando('systemctl start clamav-freshclam',
                             timeout=60)

            if ok:
                self._config['ultimo_update_db'] = \
                    datetime.now().strftime('%d/%m/%Y %H:%M')
                self._salvar_config()
                if self._daemon_ativo():
                    executar_comando('clamdscan --reload', timeout=60)
                return {'sucesso': True,
                        'mensagem': 'Banco de vírus atualizado!'}

            detalhe = (r.get('erro') or r.get('saida') or '')[-200:]
            return {'sucesso': False,
                    'erro': f'Falha ao atualizar o banco: {detalhe}'}
        except Exception as e:
            logger.error(f"av atualizar_banco: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # SCAN
    # ══════════════════════════════════════════════════════

    def iniciar_scan(self, caminho='/', tipo='completo'):
        with self._lock:
            if self._scan_ativo:
                return {'sucesso': False,
                        'erro': 'Scan já em andamento'}
            caminho = os.path.abspath(str(caminho or '/'))
            if '\x00' in caminho or not os.path.exists(caminho):
                return {'sucesso': False,
                        'erro': f'Caminho não existe: {caminho}'}
            if tipo not in ('completo', 'diario', 'rapido'):
                tipo = 'completo'
            if not self._clamav_instalado():
                return {'sucesso': False,
                        'erro': 'ClamAV não está instalado'}
            if not self._tem_banco():
                return {'sucesso': False,
                        'erro': ('Banco de vírus ausente. Use '
                                 '"Atualizar banco" primeiro.')}
            self._scan_ativo = True
            self._cancelar   = False
            self._scan_info  = {
                'tipo':                 tipo,
                'caminho':              caminho,
                'inicio':               datetime.now().isoformat(),
                'progresso':            'iniciando...',
                'arquivos_verificados': 0,
                'ameacas_encontradas':  0,
                'erros':                0,
            }

        def _rodar():
            try:
                self._executar_scan(caminho)
            except Exception as e:
                logger.error(f"av scan: {e}")
                self._scan_info['progresso'] = f'erro: {e}'
            finally:
                self._scan_info.setdefault(
                    'fim', datetime.now().isoformat())
                self._scan_ativo = False
                chave = ('ultimo_scan_completo' if tipo == 'completo'
                         else 'ultimo_scan_diario')
                self._config[chave] = \
                    datetime.now().strftime('%d/%m/%Y %H:%M')
                self._salvar_config()

        threading.Thread(target=_rodar, daemon=True,
                         name='RRFS-AV-Scan').start()
        return {'sucesso': True,
                'mensagem': f'Scan {tipo} iniciado em {caminho}'}

    def cancelar_scan(self):
        if not self._scan_ativo:
            return {'sucesso': False, 'erro': 'Nenhum scan em andamento'}
        self._cancelar = True
        return {'sucesso': True, 'mensagem': 'Cancelando scan...'}

    def status_scan(self):
        return {'ativo': self._scan_ativo, **self._scan_info}

    def _excluido(self, caminho):
        for p in EXCLUIR_SEMPRE + (self._q_path,):
            if caminho == p or caminho.startswith(p + '/'):
                return True
        return False

    def _executar_scan(self, caminho):
        info  = self._scan_info
        stamp = self._db_stamp()
        cache = self._ler_json(self._hashes_path, {})
        if (not isinstance(cache, dict) or cache.get('db') != stamp or
                not isinstance(cache.get('f'), dict)):
            cache = {'db': stamp, 'f': {}}   # banco mudou: reavalia tudo
        arq_cache = cache['f']
        ignorar = set(self._config.get('ignorar', []))

        # 1) lista o que precisa ser escaneado
        info['progresso'] = 'listando arquivos...'
        pendentes, total, cacheados = [], 0, 0
        for raiz, dirs, nomes in os.walk(caminho, followlinks=False,
                                          onerror=lambda e: None):
            if self._cancelar:
                info['progresso'] = 'cancelado'
                return
            dirs[:] = [d for d in dirs
                       if not self._excluido(os.path.join(raiz, d))]
            if self._excluido(raiz):
                continue
            for nome in nomes:
                p = os.path.join(raiz, nome)
                try:
                    p.encode('utf-8')
                    if '\n' in p or p in ignorar:
                        continue
                    st = os.lstat(p)
                    if (not stat.S_ISREG(st.st_mode) or st.st_size == 0
                            or st.st_size > TAM_MAX_ARQUIVO):
                        continue
                except (OSError, UnicodeEncodeError):
                    continue
                total += 1
                ant = arq_cache.get(p)
                if ant and ant[0] == st.st_mtime and ant[1] == st.st_size:
                    cacheados += 1
                    continue
                pendentes.append((p, st.st_mtime, st.st_size))
            info['progresso'] = f'listando... {total} arquivos'

        info['arquivos_verificados'] = cacheados
        info['progresso'] = f'{cacheados}/{total}'

        # 2) varre em lotes (nunca quarentena por erro)
        usar_daemon = self._daemon_ativo()
        tam = TAM_LOTE_DAEMON if usar_daemon else TAM_LOTE_CLAMSCAN
        ameacas = falhas = 0
        i = 0
        while i < len(pendentes):
            if self._cancelar:
                info['progresso'] = 'cancelado'
                break
            lote = pendentes[i:i + tam]
            caminhos = [p for p, _, _ in lote]
            res = self._escanear_lote(caminhos, usar_daemon)
            if res is None and usar_daemon:
                usar_daemon = False          # daemon falhou: clamscan
                tam = TAM_LOTE_CLAMSCAN
                continue
            i += len(lote)
            if res is None:
                falhas += 1
                info['erros'] += len(lote)
                if falhas >= MAX_FALHAS_SEGUIDAS:
                    info['progresso'] = ('erro: o scanner falhou '
                                         'repetidamente (verifique o '
                                         'ClamAV/banco de vírus)')
                    break
                continue
            falhas = 0
            achados, erros = res
            for p, mt, sz in lote:
                if p in achados:
                    ameacas += 1
                    info['ameacas_encontradas'] = ameacas
                    self._mover_quarentena(p, achados[p])
                elif p in erros:
                    info['erros'] += 1
                elif len(arq_cache) < MAX_ENTRADAS_CACHE:
                    arq_cache[p] = [mt, sz]
            info['arquivos_verificados'] += len(lote)
            info['progresso'] = (f"{info['arquivos_verificados']}"
                                 f"/{total}")

        self._escrever_json(self._hashes_path, cache, indent=None)
        if not info['progresso'].startswith(('erro', 'cancelado')):
            info['progresso'] = 'concluído'
        info['fim'] = datetime.now().isoformat()
        info['ameacas_encontradas'] = ameacas

    def _escanear_lote(self, caminhos, usar_daemon):
        """Retorna (achados{path: virus}, erros{path}) ou None se o
        scanner falhou por inteiro (nesse caso NADA é quarentenado)."""
        fd, lista = tempfile.mkstemp(prefix='rrfs_av_', suffix='.lst')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write('\n'.join(caminhos) + '\n')
            if usar_daemon:
                cmd = ['clamdscan', '--fdpass', '--infected',
                       '--no-summary', '-f', lista]
                limite = 900
            else:
                cmd = ['clamscan', '--infected', '--no-summary',
                       '-f', lista]
                limite = 3600
            try:
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   errors='replace', timeout=limite,
                                   env={**os.environ, **_ENV})
            except subprocess.TimeoutExpired:
                logger.error("av lote: timeout do scanner")
                return None
            except FileNotFoundError:
                logger.error(f"av lote: {cmd[0]} não encontrado")
                return None

            conjunto = set(caminhos)
            achados, erros = {}, set()
            for linha in r.stdout.splitlines():
                linha = linha.rstrip()
                if linha.endswith(' FOUND'):
                    cam, _, virus = linha[:-6].rpartition(': ')
                    if cam in conjunto:
                        achados[cam] = virus.strip() or 'desconhecido'
                elif linha.endswith(' ERROR'):
                    cam, _, _ = linha[:-6].rpartition(': ')
                    if cam in conjunto:
                        erros.add(cam)
            if r.returncode not in (0, 1) and not achados and not erros:
                logger.error(f"av lote: scanner falhou (cod "
                             f"{r.returncode}): {r.stderr[-200:]}")
                return None
            return achados, erros
        finally:
            try:
                os.remove(lista)
            except OSError:
                pass

    # ══════════════════════════════════════════════════════
    # QUARENTENA
    # ══════════════════════════════════════════════════════

    def _carregar_quarentena_meta(self):
        dados = self._ler_json(self._q_meta_path, [])
        return dados if isinstance(dados, list) else []

    def _salvar_quarentena_meta(self, meta):
        self._escrever_json(self._q_meta_path, meta)

    def _mover_quarentena(self, arquivo_orig, virus_nome):
        try:
            with self._lock:
                rid = uuid.uuid4().hex[:8]
                dest = os.path.join(
                    self._q_path,
                    f"{rid}_{os.path.basename(arquivo_orig)}")
                shutil.move(arquivo_orig, dest)
                os.chmod(dest, 0o600)
                meta = self._carregar_quarentena_meta()
                meta.append({
                    'id':           rid,
                    'arquivo_orig': arquivo_orig,
                    'arquivo_q':    dest,
                    'virus':        virus_nome,
                    'data':         datetime.now().isoformat(),
                    'tamanho':      os.path.getsize(dest),
                })
                self._salvar_quarentena_meta(meta)
        except Exception as e:
            logger.error(f"av _mover_quarentena: {e}")

    def _sincronizar_quarentena(self, meta):
        """Inclui arquivos movidos pelo cron (--move), sem metadados."""
        conhecidos = {m.get('arquivo_q') for m in meta}
        mudou = False
        try:
            for nome in os.listdir(self._q_path):
                p = os.path.join(self._q_path, nome)
                if p in conhecidos or not os.path.isfile(p):
                    continue
                meta.append({
                    'id':           uuid.uuid4().hex[:8],
                    'arquivo_orig': '',
                    'arquivo_q':    p,
                    'virus':        'Detectado por scan agendado',
                    'data':         datetime.fromtimestamp(
                        os.path.getmtime(p)).isoformat(),
                    'tamanho':      os.path.getsize(p),
                })
                mudou = True
        except Exception as e:
            logger.error(f"av sincronizar_quarentena: {e}")
        if mudou:
            self._salvar_quarentena_meta(meta)
        return meta

    def listar_quarentena(self):
        with self._lock:
            meta = self._carregar_quarentena_meta()
            return self._sincronizar_quarentena(meta)

    def restaurar_quarentena(self, rid):
        try:
            with self._lock:
                meta = self._carregar_quarentena_meta()
                for i, item in enumerate(meta):
                    if item.get('id') != rid:
                        continue
                    orig, arq_q = item.get('arquivo_orig', ''), \
                        item.get('arquivo_q', '')
                    if not orig:
                        return {'sucesso': False,
                                'erro': ('Origem desconhecida (detectado '
                                         'por scan agendado). Remova ou '
                                         'restaure manualmente.')}
                    if not os.path.exists(arq_q):
                        return {'sucesso': False,
                                'erro': 'Arquivo não encontrado'}
                    if os.path.exists(orig):
                        return {'sucesso': False,
                                'erro': 'Já existe um arquivo no destino'}
                    os.makedirs(os.path.dirname(orig), exist_ok=True)
                    shutil.move(arq_q, orig)
                    meta.pop(i)
                    self._salvar_quarentena_meta(meta)
                    # falso positivo: não reescanear/quarentenar de novo
                    ign = self._config.setdefault('ignorar', [])
                    if orig not in ign:
                        ign.append(orig)
                        self._salvar_config()
                    return {'sucesso': True,
                            'mensagem': f'Restaurado: {orig}'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"av restaurar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_quarentena(self, rid):
        try:
            with self._lock:
                meta = self._carregar_quarentena_meta()
                for i, item in enumerate(meta):
                    if item.get('id') == rid:
                        arq_q = item.get('arquivo_q', '')
                        if arq_q and os.path.exists(arq_q):
                            os.remove(arq_q)
                        meta.pop(i)
                        self._salvar_quarentena_meta(meta)
                        return {'sucesso': True,
                                'mensagem': 'Removido permanentemente'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"av remover_quarentena: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── proteção "tempo real" (daemon) ────────────────────

    def configurar_protecao_tempo_real(self, ativo):
        try:
            if ativo:
                if not self._tem_banco():
                    return {'sucesso': False,
                            'erro': ('Sem banco de vírus. Atualize o '
                                     'banco primeiro.')}
                executar_comando('systemctl enable clamav-daemon',
                                 timeout=15)
                # clamd leva até ~1-2 min para carregar o banco em SBC
                executar_comando('systemctl start clamav-daemon',
                                 timeout=240)
                if not self._daemon_ativo():
                    return {'sucesso': False,
                            'erro': ('O daemon não iniciou. Veja '
                                     '/var/log/clamav/clamav.log')}
            else:
                executar_comando('systemctl stop clamav-daemon',
                                 timeout=60)
                executar_comando('systemctl disable clamav-daemon',
                                 timeout=15)
            self._config['protecao_tempo_real'] = bool(ativo)
            self._salvar_config()
            msg = ('Daemon ClamAV ativado (varreduras mais rápidas). '
                   'Não monitora acessos em tempo real.'
                   if ativo else 'Daemon ClamAV desativado.')
            return {'sucesso': True, 'mensagem': msg}
        except Exception as e:
            logger.error(f"av protecao_tempo_real: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── caminhos extras ───────────────────────────────────

    def gerenciar_caminho(self, acao, caminho):
        try:
            caminho = str(caminho or '').strip()
            if not caminho.startswith('/') or '\x00' in caminho:
                return {'sucesso': False,
                        'erro': 'Informe um caminho absoluto'}
            caminho = os.path.normpath(caminho)
            caminhos = self._config.setdefault('caminhos_extras', [])
            if acao == 'adicionar':
                if not os.path.exists(caminho):
                    return {'sucesso': False,
                            'erro': f'Não existe: {caminho}'}
                if caminho not in caminhos:
                    caminhos.append(caminho)
                    self._salvar_config()
                    if self._config.get('instalado'):
                        self._configurar_cron()
                return {'sucesso': True,
                        'mensagem': f'Adicionado: {caminho}'}
            if acao == 'remover':
                if caminho in caminhos:
                    caminhos.remove(caminho)
                    self._salvar_config()
                    if self._config.get('instalado'):
                        self._configurar_cron()
                return {'sucesso': True,
                        'mensagem': f'Removido: {caminho}'}
            return {'sucesso': False, 'erro': 'Ação inválida'}
        except Exception as e:
            logger.error(f"av gerenciar_caminho: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── cron ──────────────────────────────────────────────

    def _configurar_cron(self):
        """Script + cron.d. Usa o daemon se ativo; exclui quarentena,
        /proc, /sys, /dev, /run e docker; flock evita scans
        sobrepostos."""
        try:
            q = self._q_path
            diarios = []
            for d in (self._config.get('scan_diario_dirs', []) +
                      self._config.get('caminhos_extras', [])):
                if d not in diarios and os.path.exists(d):
                    diarios.append(d)
            lista_diaria = ' '.join(shlex.quote(d) for d in diarios) \
                or '/tmp'

            script = (
                '#!/bin/sh\n'
                '# RRFS - varredura ClamAV (gerado automaticamente)\n'
                f'Q={shlex.quote(q)}\n'
                'MODO="$1"\n'
                'if [ "$MODO" = "semanal" ]; then ALVOS="/"; '
                f'else ALVOS="{lista_diaria}"; fi\n'
                'EXCL="--exclude-dir=^/proc --exclude-dir=^/sys '
                '--exclude-dir=^/dev --exclude-dir=^/run '
                '--exclude-dir=^/var/lib/docker --exclude-dir=^$Q"\n'
                'if systemctl is-active --quiet clamav-daemon; then\n'
                '  eval clamdscan --fdpass --multiscan --infected '
                '--no-summary --move="$Q" $ALVOS\n'
                'else\n'
                '  eval clamscan -r -i --no-summary --move="$Q" '
                '$EXCL $ALVOS\n'
                'fi\n'
                'exit 0\n'
            )
            with open(SCRIPT_SCAN, 'w') as f:
                f.write(script)
            os.chmod(SCRIPT_SCAN, 0o755)

            cron = (
                '# RRFS Servidores - ClamAV\n'
                '# Scan diário dirs estratégicos (2h)\n'
                f'0 2 * * * root flock -n /run/rrfs-clamscan.lock '
                f'{SCRIPT_SCAN} diario '
                '>> /var/log/clamav/scan_diario.log 2>&1\n'
                '# Scan completo semanal (dom 3h)\n'
                f'0 3 * * 0 root flock -n /run/rrfs-clamscan.lock '
                f'{SCRIPT_SCAN} semanal '
                '>> /var/log/clamav/scan_semanal.log 2>&1\n'
            )
            with open('/etc/cron.d/rrfs-clamav', 'w') as f:
                f.write(cron)
            os.chmod('/etc/cron.d/rrfs-clamav', 0o644)
        except Exception as e:
            logger.error(f"av _configurar_cron: {e}")
