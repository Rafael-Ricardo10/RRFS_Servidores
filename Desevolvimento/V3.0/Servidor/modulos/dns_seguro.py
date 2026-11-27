#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Seguro com Unbound - RRFS Servidores v2.0
Root servers + cache + estatísticas
Corrigido: socket /run/unbound.ctl, boot automático
"""

import os
import re
import json
import time
import shutil
import logging
import threading
from datetime import datetime
from pathlib import Path

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.DNS')

UNBOUND_CONF   = '/etc/unbound/unbound.conf'
UNBOUND_CONF_D = '/etc/unbound/unbound.conf.d'
RRFS_CONF      = '/etc/unbound/unbound.conf.d/rrfs.conf'
ROOT_HINTS     = '/var/lib/unbound/root.hints'
RESOLV_CONF    = '/etc/resolv.conf'
RESOLV_SYSTEMD = '/etc/systemd/resolved.conf'

# Caminho EXATO permitido pelo AppArmor do Debian
# Verificado em /etc/apparmor.d/usr.sbin.unbound:
#   /run/unbound.ctl rw,
UNBOUND_CTL = '/run/unbound.ctl'


class DNSSeguro:

    def __init__(self, base_dir):
        self.base_dir  = base_dir
        self._cfg_path = os.path.join(
            base_dir, 'dados', 'dns_config.json'
        )
        self._config   = self._carregar()
        self._firewall = None
        self._lock     = threading.Lock()

    def set_firewall(self, fw):
        self._firewall = fw

    # ── config ────────────────────────────────────────────

    def _carregar(self):
        try:
            if os.path.exists(self._cfg_path):
                with open(self._cfg_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"dns carregar: {e}")
        return {
            'ativo': False,
            'porta': 53,
            'tem_filtro_externo': False,
        }

    def _salvar(self):
        try:
            os.makedirs(
                os.path.dirname(self._cfg_path),
                exist_ok=True
            )
            with open(self._cfg_path, 'w') as f:
                json.dump(self._config, f,
                          indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"dns salvar: {e}")

    # ── status ────────────────────────────────────────────

    def obter_status(self):
        try:
            instalado = self._unbound_instalado()
            ativo     = False
            if instalado:
                r = executar_comando(
                    'systemctl is-active unbound 2>/dev/null'
                )
                ativo = (r['sucesso'] and
                         'active' in r.get('saida', ''))

            # sincronizar config com realidade
            if ativo and not self._config.get('ativo'):
                self._config['ativo'] = True
                self._salvar()
            elif not ativo and self._config.get('ativo'):
                self._config['ativo'] = False
                self._salvar()

            stats = self._obter_stats_unbound()

            return {
                'instalado':          instalado,
                'ativo':              ativo,
                'porta':              self._config.get(
                    'porta', 53
                ),
                'tem_filtro_externo': self._config.get(
                    'tem_filtro_externo', False
                ),
                'cache_total':    stats.get('cache_total', 0),
                'cache_hits':     stats.get('cache_hits', 0),
                'cache_miss':     stats.get('cache_miss', 0),
                'pct_cache':      stats.get('pct_cache', 0),
                'pct_unbound':    stats.get('pct_unbound', 0),
                'total_queries':  stats.get('total_queries', 0),
                'dominios_top':   stats.get('dominios_top', []),
                'tempo_medio_ms': stats.get(
                    'tempo_medio_ms', 0
                ),
                'systemd_resolved': (
                    self._systemd_resolved_ativo()
                ),
            }
        except Exception as e:
            logger.error(f"dns obter_status: {e}")
            return {'instalado': False, 'ativo': False}

    def obter_status_resumido(self):
        try:
            r = executar_comando(
                'systemctl is-active unbound 2>/dev/null'
            )
            ativo = (r['sucesso'] and
                     'active' in r.get('saida', ''))
            return {
                'ativo':     ativo,
                'porta':     self._config.get('porta', 53),
                'instalado': self._unbound_instalado()
            }
        except Exception as e:
            logger.error(f"dns status_resumido: {e}")
            return {'ativo': False, 'porta': 53}

    def _unbound_instalado(self):
        r = executar_comando('which unbound 2>/dev/null')
        return r['sucesso']

    def _systemd_resolved_ativo(self):
        r = executar_comando(
            'systemctl is-active systemd-resolved 2>/dev/null'
        )
        return (r['sucesso'] and
                'active' in r.get('saida', ''))

    # ══════════════════════════════════════════════════════
    # ATIVAR - FLUXO COMPLETO
    # ══════════════════════════════════════════════════════

    def ativar(self):
        with self._lock:
            try:
                # 1. instalar se necessário
                if not self._unbound_instalado():
                    r = executar_comando(
                        'apt-get install -y unbound dnsutils',
                        timeout=300
                    )
                    if not r['sucesso']:
                        return {
                            'sucesso': False,
                            'erro': 'Falha ao instalar Unbound'
                        }

                # 2. parar antes de reconfigurar
                executar_comando(
                    'systemctl stop unbound 2>/dev/null',
                    timeout=15
                )
                time.sleep(2)

                # 3. desativar systemd-resolved
                if self._systemd_resolved_ativo():
                    executar_comando(
                        'systemctl stop systemd-resolved',
                        timeout=15
                    )
                    executar_comando(
                        'systemctl disable systemd-resolved',
                        timeout=15
                    )
                    self._fazer_backup(
                        '/etc/systemd/resolved.conf'
                    )

                # 4. corrigir root.key
                self._corrigir_root_key()

                # 5. baixar root hints
                self._baixar_root_hints()

                # 6. corrigir permissões
                self._corrigir_permissoes()

                # 7. AppArmor
                self._ajustar_apparmor_unbound()

                # 8. limpar configs conflitantes
                self._limpar_configs_conflitantes()

                # 9. gerar nossa configuração
                porta = self._config.get('porta', 53)
                self._gerar_conf_unbound(porta)

                # 10. DNS temporário durante reinício
                self._fazer_backup(RESOLV_CONF)
                self._configurar_resolv_temp()

                # 11. configurar boot automático
                self._configurar_boot_dns()

                # 12. recarregar systemd
                executar_comando(
                    'systemctl daemon-reload', timeout=15
                )

                # 13. iniciar unbound
                executar_comando(
                    'systemctl enable unbound', timeout=15
                )
                executar_comando(
                    'systemctl restart unbound', timeout=30
                )
                time.sleep(4)

                # 14. verificar
                r2 = executar_comando(
                    'systemctl is-active unbound', timeout=10
                )
                if 'active' not in r2.get('saida', ''):
                    err = executar_comando(
                        'journalctl -u unbound -n 30 '
                        '--no-pager 2>/dev/null',
                        timeout=10
                    )
                    return {
                        'sucesso': False,
                        'erro': (
                            f"Unbound não iniciou: "
                            f"{err.get('saida', '')}"
                        )
                    }

                # 15. apontar DNS para unbound
                self._configurar_resolv_unbound(porta)

                # 16. UFW
                self._criar_regra_ufw_dns(porta)

                self._config['ativo'] = True
                self._salvar()

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'DNS Seguro ativado! '
                        f'Unbound porta {porta}. '
                        f'Ativo automaticamente no boot.'
                    )
                }
            except Exception as e:
                logger.error(f"dns ativar: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # BOOT AUTOMÁTICO
    # ══════════════════════════════════════════════════════

    def _configurar_boot_dns(self):
        """
        Garante que após reboot:
        1. Unbound inicia automaticamente (systemctl enable)
        2. resolv.conf aponta para 127.0.0.1
        3. Um serviço one-shot corrige o resolv.conf
           após o Unbound iniciar
        """
        try:
            # ── script que corrige resolv.conf no boot ──
            script = """\
#!/bin/bash
# RRFS - Garantir DNS após boot
# Executado pelo systemd após unbound iniciar

RESOLV=/etc/resolv.conf

# Obter porta configurada
PORTA=$(grep -oP '(?<=port: )\\d+' \
    /etc/unbound/unbound.conf.d/rrfs.conf \
    2>/dev/null || echo "53")

# Só alterar se unbound estiver ativo
if systemctl is-active --quiet unbound; then
    # Remover symlink se existir (systemd-resolved)
    if [ -L "$RESOLV" ]; then
        rm -f "$RESOLV"
    fi

    if [ "$PORTA" = "53" ]; then
        cat > "$RESOLV" << 'RESOLVEOF'
# RRFS Servidores - DNS via Unbound
nameserver 127.0.0.1
options ndots:1
RESOLVEOF
    else
        printf '# RRFS - Unbound porta %s\\nnameserver 127.0.0.1\\nnameserver 1.1.1.1\\n' \
            "$PORTA" > "$RESOLV"
    fi
fi
"""
            script_path = '/usr/local/bin/rrfs-dns-boot.sh'
            with open(script_path, 'w') as f:
                f.write(script)
            os.chmod(script_path, 0o755)

            # ── serviço systemd one-shot ──────────────
            svc = """\
[Unit]
Description=RRFS - Configurar DNS apos boot
Documentation=https://github.com/rrfs
After=unbound.service network-online.target
Wants=network-online.target
Requires=unbound.service
ConditionPathExists=/etc/unbound/unbound.conf.d/rrfs.conf

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rrfs-dns-boot.sh
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""
            svc_path = (
                '/etc/systemd/system/'
                'rrfs-dns-boot.service'
            )
            with open(svc_path, 'w') as f:
                f.write(svc)

            executar_comando(
                'systemctl daemon-reload', timeout=15
            )
            executar_comando(
                'systemctl enable rrfs-dns-boot.service',
                timeout=10
            )

            logger.error(
                "dns _configurar_boot_dns: configurado"
            )

        except Exception as e:
            logger.error(f"dns _configurar_boot_dns: {e}")

    # ══════════════════════════════════════════════════════
    # DESATIVAR
    # ══════════════════════════════════════════════════════

    def desativar(self):
        with self._lock:
            try:
                # desativar serviço de boot também
                executar_comando(
                    'systemctl disable '
                    'rrfs-dns-boot.service 2>/dev/null',
                    timeout=10
                )

                executar_comando(
                    'systemctl stop unbound', timeout=15
                )
                executar_comando(
                    'systemctl disable unbound', timeout=15
                )

                self._restaurar_backup(RESOLV_CONF)

                bkp = RESOLV_SYSTEMD + '.rrfs.bak'
                if os.path.exists(bkp):
                    executar_comando(
                        'systemctl enable systemd-resolved',
                        timeout=15
                    )
                    executar_comando(
                        'systemctl start systemd-resolved',
                        timeout=15
                    )
                    self._restaurar_backup(RESOLV_SYSTEMD)

                self._remover_regra_ufw_dns()
                self._config['ativo'] = False
                self._salvar()

                return {
                    'sucesso': True,
                    'mensagem': 'DNS Seguro desativado.'
                }
            except Exception as e:
                logger.error(f"dns desativar: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # CORREÇÕES
    # ══════════════════════════════════════════════════════

    def _ajustar_apparmor_unbound(self):
        """
        Perfil AppArmor principal permite:
          /run/unbound.ctl rw,   ← socket correto
          /var/lib/unbound/** rw,

        Adicionamos apenas:
          /var/log/unbound/      ← nosso log
          /etc/unbound/unbound.conf.d/  ← nossa config
        """
        try:
            local_dir = '/etc/apparmor.d/local'
            local_f   = f'{local_dir}/usr.sbin.unbound'
            os.makedirs(local_dir, exist_ok=True)

            adicoes = """\
# RRFS - permissoes adicionais para Unbound
# Gerado automaticamente pelo RRFS

# Log personalizado
/var/log/unbound/ rw,
/var/log/unbound/** rw,

# Configuracoes RRFS
/etc/unbound/unbound.conf.d/ r,
/etc/unbound/unbound.conf.d/** r,

# Root hints
/var/lib/unbound/root.hints r,
/var/lib/unbound/root.key rw,
"""
            with open(local_f, 'w') as f:
                f.write(adicoes)

            perfil = '/etc/apparmor.d/usr.sbin.unbound'
            if os.path.exists(perfil):
                r = executar_comando(
                    f'apparmor_parser -r "{perfil}" 2>&1',
                    timeout=15
                )
                if not r['sucesso']:
                    logger.error(
                        f"apparmor_parser unbound: "
                        f"{r.get('saida','')} "
                        f"{r.get('erro','')}"
                    )
            else:
                executar_comando(
                    'systemctl reload apparmor 2>/dev/null',
                    timeout=15
                )

            time.sleep(1)

        except Exception as e:
            logger.error(f"dns _ajustar_apparmor: {e}")

    def _corrigir_root_key(self):
        """Remove root.key corrompido e regenera"""
        try:
            root_key = '/var/lib/unbound/root.key'

            if os.path.exists(root_key):
                os.remove(root_key)

            executar_comando(
                'chown -R unbound:unbound /var/lib/unbound',
                timeout=10
            )

            executar_comando(
                'unbound-anchor '
                '-a /var/lib/unbound/root.key '
                '2>/dev/null || true',
                timeout=30
            )

            if os.path.exists(root_key):
                executar_comando(
                    f'chown unbound:unbound {root_key}'
                )
                executar_comando(f'chmod 644 {root_key}')
                return True

            self._criar_root_key_fallback(root_key)
            return True

        except Exception as e:
            logger.error(f"dns _corrigir_root_key: {e}")
            return False

    def _criar_root_key_fallback(self, root_key):
        conteudo = (
            '. IN DS 20326 8 2 '
            'E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457'
            '104237C7F8EC8D\n'
        )
        try:
            with open(root_key, 'w') as f:
                f.write(conteudo)
            executar_comando(
                f'chown unbound:unbound {root_key}'
            )
            executar_comando(f'chmod 644 {root_key}')
        except Exception as e:
            logger.error(f"_root_key_fallback: {e}")

    def _corrigir_permissoes(self):
        try:
            cmds = [
                'mkdir -p /var/log/unbound',
                'chown -R unbound:unbound /var/log/unbound',
                'chmod 755 /var/log/unbound',
                'chown -R unbound:unbound /var/lib/unbound',
                'chmod 755 /var/lib/unbound',
            ]
            for c in cmds:
                executar_comando(c, timeout=10)
        except Exception as e:
            logger.error(f"dns _corrigir_permissoes: {e}")

    def _limpar_configs_conflitantes(self):
        """
        Remove arquivos do Debian que conflitam com nossa config.

        O Debian instala automaticamente em unbound.conf.d/:
        - remote-control.conf     → duplica nosso remote-control
        - root-auto-trust-anchor-file.conf → duplica nosso trust-anchor

        Nossa rrfs.conf já contém tudo que precisamos.
        Manter esses arquivos causa erro 'option presented twice'.
        """
        try:
            # backup do unbound.conf principal
            if not os.path.exists(UNBOUND_CONF):
                return

            bkp = UNBOUND_CONF + '.debian.bak'
            if not os.path.exists(bkp):
                shutil.copy2(UNBOUND_CONF, bkp)

            # arquivos do Debian que conflitam com nossa config
            conflitantes = [
                os.path.join(
                    UNBOUND_CONF_D,
                    'remote-control.conf'
                ),
                os.path.join(
                    UNBOUND_CONF_D,
                    'root-auto-trust-anchor-file.conf'
                ),
            ]

            for arq in conflitantes:
                if os.path.exists(arq):
                    # backup antes de remover
                    bkp_arq = arq + '.rrfs.bak'
                    if not os.path.exists(bkp_arq):
                        shutil.copy2(arq, bkp_arq)
                    os.remove(arq)
                    logger.error(
                        f"dns: removido conflitante: {arq}"
                    )

            # substituir unbound.conf por versão limpa
            with open(UNBOUND_CONF, 'w') as f:
                f.write(
                    '# RRFS Servidores - unbound.conf\n'
                    '# Gerenciado automaticamente\n\n'
                    f'include-toplevel: '
                    f'"{UNBOUND_CONF_D}/*.conf"\n'
                )

        except Exception as e:
            logger.error(f"dns _limpar_configs: {e}")

    # ══════════════════════════════════════════════════════
    # CONFIGURAÇÃO UNBOUND
    # ══════════════════════════════════════════════════════

    def _gerar_conf_unbound(self, porta=53):
        """
        CORREÇÃO PRINCIPAL:
        control-interface: /run/unbound.ctl
        (sem subdiretório - caminho exato do AppArmor)
        """
        try:
            os.makedirs(UNBOUND_CONF_D, exist_ok=True)

            conf = f"""\
# RRFS Servidores - Configuracao Unbound
# Gerado em: {datetime.now().isoformat()}
# NAO EDITE - gerenciado pelo RRFS

server:
    # Rede
    port: {porta}
    interface: 127.0.0.1
    interface: 0.0.0.0

    # Acesso
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8  allow
    access-control: 192.168.0.0/16 allow
    access-control: 172.16.0.0/12 allow
    access-control: 0.0.0.0/0   refuse

    # Root hints
    root-hints: "{ROOT_HINTS}"

    # DNSSEC - unico trust anchor
    auto-trust-anchor-file: "/var/lib/unbound/root.key"

    # Performance
    num-threads: 2
    msg-cache-size: 64m
    rrset-cache-size: 128m
    cache-min-ttl: 300
    cache-max-ttl: 86400
    prefetch: yes

    # Privacidade
    hide-identity: yes
    hide-version: yes
    qname-minimisation: yes

    # Log
    verbosity: 0
    log-queries: no
    log-replies: no
    use-syslog: no
    logfile: "/var/log/unbound/unbound.log"

    # Seguranca
    harden-glue: yes
    harden-dnssec-stripped: yes
    harden-below-nxdomain: yes
    harden-referral-path: yes
    unwanted-reply-threshold: 10000000

    # Protocolo
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    # Usuario
    username: "unbound"
    directory: "/etc/unbound"
    chroot: ""

# Controle Remoto
# CAMINHO EXATO permitido pelo AppArmor:
# /run/unbound.ctl (sem subdiretorio!)
# Verificado em /etc/apparmor.d/usr.sbin.unbound
remote-control:
    control-enable: yes
    control-interface: /run/unbound.ctl
    control-use-cert: no
"""
            with open(RRFS_CONF, 'w') as f:
                f.write(conf)

            executar_comando(
                f'chown root:unbound {RRFS_CONF} 2>/dev/null'
            )
            executar_comando(f'chmod 640 {RRFS_CONF}')

            executar_comando('mkdir -p /var/log/unbound')
            executar_comando(
                'chown unbound:unbound /var/log/unbound'
            )
            executar_comando('chmod 755 /var/log/unbound')

            self._garantir_include_conf()

        except Exception as e:
            logger.error(f"dns _gerar_conf: {e}")

    def _garantir_include_conf(self):
        try:
            if not os.path.exists(UNBOUND_CONF):
                with open(UNBOUND_CONF, 'w') as f:
                    f.write(
                        '# RRFS - unbound.conf\n'
                        f'include-toplevel: '
                        f'"{UNBOUND_CONF_D}/*.conf"\n'
                    )
                return

            with open(UNBOUND_CONF, 'r') as f:
                conteudo = f.read()

            inc = (
                f'include-toplevel: '
                f'"{UNBOUND_CONF_D}/*.conf"'
            )
            if inc not in conteudo:
                with open(UNBOUND_CONF, 'a') as f:
                    f.write(f'\n{inc}\n')
        except Exception as e:
            logger.error(f"dns _garantir_include: {e}")

    # ── root hints ────────────────────────────────────────

    def _baixar_root_hints(self):
        try:
            os.makedirs(
                os.path.dirname(ROOT_HINTS), exist_ok=True
            )
            r = executar_comando(
                f'curl -s --max-time 30 '
                f'https://www.internic.net/domain/named.root '
                f'-o {ROOT_HINTS}',
                timeout=35
            )
            if r['sucesso'] and os.path.exists(ROOT_HINTS):
                executar_comando(
                    f'chown unbound:unbound {ROOT_HINTS}'
                )
                executar_comando(f'chmod 644 {ROOT_HINTS}')
                return True
            self._criar_root_hints_fallback()
            return True
        except Exception as e:
            logger.error(f"dns _baixar_root_hints: {e}")
            self._criar_root_hints_fallback()
            return False

    def _criar_root_hints_fallback(self):
        hints = """\
;  Root hints - RRFS fallback
.  3600000  IN  NS  a.root-servers.net.
a.root-servers.net.  3600000  A   198.41.0.4
.  3600000  IN  NS  b.root-servers.net.
b.root-servers.net.  3600000  A   199.9.14.201
.  3600000  IN  NS  c.root-servers.net.
c.root-servers.net.  3600000  A   192.33.4.12
.  3600000  IN  NS  d.root-servers.net.
d.root-servers.net.  3600000  A   199.7.91.13
.  3600000  IN  NS  e.root-servers.net.
e.root-servers.net.  3600000  A   192.203.230.10
.  3600000  IN  NS  f.root-servers.net.
f.root-servers.net.  3600000  A   192.5.5.241
.  3600000  IN  NS  g.root-servers.net.
g.root-servers.net.  3600000  A   192.112.36.4
.  3600000  IN  NS  h.root-servers.net.
h.root-servers.net.  3600000  A   198.97.190.53
.  3600000  IN  NS  i.root-servers.net.
i.root-servers.net.  3600000  A   192.36.148.17
.  3600000  IN  NS  j.root-servers.net.
j.root-servers.net.  3600000  A   192.58.128.30
.  3600000  IN  NS  k.root-servers.net.
k.root-servers.net.  3600000  A   193.0.14.129
.  3600000  IN  NS  l.root-servers.net.
l.root-servers.net.  3600000  A   199.7.83.42
.  3600000  IN  NS  m.root-servers.net.
m.root-servers.net.  3600000  A   202.12.27.33
"""
        try:
            os.makedirs(
                os.path.dirname(ROOT_HINTS), exist_ok=True
            )
            with open(ROOT_HINTS, 'w') as f:
                f.write(hints)
            executar_comando(
                f'chown unbound:unbound {ROOT_HINTS}'
            )
            executar_comando(f'chmod 644 {ROOT_HINTS}')
        except Exception as e:
            logger.error(f"dns _root_hints_fallback: {e}")

    # ── resolv.conf ───────────────────────────────────────

    def _configurar_resolv_temp(self):
        try:
            if os.path.islink(RESOLV_CONF):
                os.unlink(RESOLV_CONF)
            with open(RESOLV_CONF, 'w') as f:
                f.write(
                    "# RRFS - DNS temporario\n"
                    "nameserver 1.1.1.1\n"
                    "nameserver 8.8.8.8\n"
                )
        except Exception as e:
            logger.error(f"dns _resolv_temp: {e}")

    def _configurar_resolv_unbound(self, porta=53):
        try:
            if os.path.islink(RESOLV_CONF):
                os.unlink(RESOLV_CONF)
            if porta == 53:
                with open(RESOLV_CONF, 'w') as f:
                    f.write(
                        "# RRFS - DNS via Unbound\n"
                        "nameserver 127.0.0.1\n"
                        "options ndots:1\n"
                    )
            else:
                with open(RESOLV_CONF, 'w') as f:
                    f.write(
                        f"# RRFS - Unbound porta {porta}\n"
                        "nameserver 127.0.0.1\n"
                        "nameserver 1.1.1.1\n"
                    )
        except Exception as e:
            logger.error(f"dns _resolv_unbound: {e}")

    # ── backup / restore ──────────────────────────────────

    def _fazer_backup(self, arquivo):
        bkp = arquivo + '.rrfs.bak'
        try:
            if (os.path.exists(arquivo) and
                    not os.path.islink(arquivo) and
                    not os.path.exists(bkp)):
                shutil.copy2(arquivo, bkp)
        except Exception as e:
            logger.error(
                f"dns _fazer_backup {arquivo}: {e}"
            )

    def _restaurar_backup(self, arquivo):
        bkp = arquivo + '.rrfs.bak'
        try:
            if os.path.exists(bkp):
                if os.path.islink(arquivo):
                    os.unlink(arquivo)
                shutil.copy2(bkp, arquivo)
                os.remove(bkp)
        except Exception as e:
            logger.error(
                f"dns _restaurar_backup {arquivo}: {e}"
            )

    # ── configurar porta ──────────────────────────────────

    def configurar_porta(self, porta,
                          tem_filtro_externo=False):
        try:
            porta = int(porta)
            if not (1 <= porta <= 65535):
                return {
                    'sucesso': False,
                    'erro': 'Porta inválida'
                }

            self._config['porta']              = porta
            self._config['tem_filtro_externo'] = \
                tem_filtro_externo
            self._salvar()

            self._gerar_conf_unbound(porta)
            r = executar_comando(
                'systemctl restart unbound', timeout=30
            )
            if not r['sucesso']:
                return {
                    'sucesso': False,
                    'erro': 'Falha ao reiniciar Unbound'
                }

            if not tem_filtro_externo:
                self._configurar_resolv_unbound(porta)

            self._remover_regra_ufw_dns()
            self._criar_regra_ufw_dns(porta)

            aviso = ''
            if porta != 53:
                aviso = (
                    f' ⚠️ Porta {porta} ≠ 53. '
                    f'Use filtro DNS externo apontando '
                    f'para 127.0.0.1:{porta}.'
                )
            return {
                'sucesso': True,
                'mensagem': f'Porta DNS: {porta}.{aviso}',
                'porta':    porta,
                'aviso':    aviso
            }
        except ValueError:
            return {'sucesso': False, 'erro': 'Porta inválida'}
        except Exception as e:
            logger.error(f"dns configurar_porta: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── estatísticas ──────────────────────────────────────

    def obter_estatisticas(self):
        try:
            stats = self._obter_stats_unbound()
            cache = self.obter_cache()
            return {
                **stats,
                'cache_entries': cache[:20],
                'porta':         self._config.get('porta', 53),
                'ativo':         self._config.get('ativo', False)
            }
        except Exception as e:
            logger.error(f"dns obter_estatisticas: {e}")
            return {}

    def _obter_stats_unbound(self):
        try:
            r = executar_comando(
                'unbound-control stats_noreset 2>/dev/null',
                timeout=10
            )
            if not r['sucesso'] or not r['saida']:
                return {}

            dados = {}
            for linha in r['saida'].splitlines():
                if '=' in linha:
                    k, v = linha.split('=', 1)
                    try:
                        dados[k.strip()] = float(v.strip())
                    except Exception:
                        dados[k.strip()] = v.strip()

            total = dados.get('total.num.queries', 0)
            hits  = dados.get('total.num.cachehits', 0)
            miss  = dados.get('total.num.cachemiss', 0)
            pct_c = round(
                (hits / total * 100) if total > 0 else 0, 1
            )
            t_med = dados.get(
                'total.recursion.time.avg', 0
            )

            return {
                'total_queries':  int(total),
                'cache_hits':     int(hits),
                'cache_miss':     int(miss),
                'cache_total':    int(hits + miss),
                'pct_cache':      pct_c,
                'pct_unbound':    round(100 - pct_c, 1),
                'tempo_medio_ms': round(
                    float(t_med) * 1000, 2
                ),
                'dominios_top':   self._top_dominios(),
            }
        except Exception as e:
            logger.error(f"dns _obter_stats: {e}")
            return {}

    def _top_dominios(self):
        try:
            log_f = '/var/log/unbound/unbound.log'
            if not os.path.exists(log_f):
                return []
            r = executar_comando(
                f"grep -oP 'info: [A-Za-z0-9._-]+\\.' "
                f"{log_f} 2>/dev/null | "
                f"sed 's/info: //' | "
                f"sort | uniq -c | sort -rn | head -10",
                timeout=10
            )
            dominios = []
            if r['sucesso'] and r['saida']:
                for linha in r['saida'].splitlines():
                    p = linha.strip().split(None, 1)
                    if len(p) == 2:
                        dominios.append({
                            'dominio': p[1].rstrip('.'),
                            'count':   int(p[0])
                        })
            return dominios
        except Exception as e:
            logger.error(f"dns _top_dominios: {e}")
            return []

    def obter_cache(self):
        try:
            r = executar_comando(
                'unbound-control dump_cache 2>/dev/null',
                timeout=15
            )
            if not r['sucesso'] or not r['saida']:
                return []
            entradas = []
            for linha in r['saida'].splitlines():
                p = linha.strip().split()
                if len(p) >= 4 and p[0] not in [
                    'START_RRSET_CACHE', 'END_RRSET_CACHE',
                    'START_MSG_CACHE', 'END_MSG_CACHE', ''
                ]:
                    try:
                        entradas.append({
                            'dominio': p[0].rstrip('.'),
                            'ttl':     int(p[1]),
                            'tipo':    p[3] if len(p) > 3
                                       else '--',
                            'valor':   p[4] if len(p) > 4
                                       else '--',
                        })
                    except Exception:
                        pass
            return entradas[:100]
        except Exception as e:
            logger.error(f"dns obter_cache: {e}")
            return []

    def limpar_cache(self):
        try:
            r = executar_comando(
                'unbound-control flush_zone . 2>/dev/null',
                timeout=10
            )
            if r['sucesso']:
                return {
                    'sucesso': True,
                    'mensagem': 'Cache DNS limpo!'
                }
            return {
                'sucesso': False,
                'erro': 'Falha ao limpar cache'
            }
        except Exception as e:
            logger.error(f"dns limpar_cache: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── UFW ───────────────────────────────────────────────

    def _criar_regra_ufw_dns(self, porta):
        if not self._firewall:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            for proto in ['tcp', 'udp']:
                self._firewall.adicionar_regra_automatica(
                    f'DNS:{porta}:{proto}',
                    {
                        'nome':      f'DNS Seguro porta {porta}',
                        'interface': 'lo',
                        'direcao':   'in',
                        'protocolo': proto,
                        'ip':        '127.0.0.0/8',
                        'porta':     str(porta)
                    },
                    FirewallUFW.CAT_SISTEMA
                )
        except Exception as e:
            logger.error(f"dns _criar_regra_ufw: {e}")

    def _remover_regra_ufw_dns(self):
        if not self._firewall:
            return
        try:
            regras = [
                r for r in self._firewall.regras
                if r.get('nome', '').startswith(
                    'DNS Seguro'
                )
            ]
            for r in regras:
                self._firewall.remover_regra(
                    r.get('id', '')
                )
        except Exception as e:
            logger.error(f"dns _remover_regra_ufw: {e}")

    def notificar_mudanca_conexao(self):
        try:
            if self._config.get('ativo'):
                executar_comando(
                    'systemctl reload unbound', timeout=10
                )
        except Exception as e:
            logger.error(f"dns notificar_mudanca: {e}")
