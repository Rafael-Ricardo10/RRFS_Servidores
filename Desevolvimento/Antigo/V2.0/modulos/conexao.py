#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Conexão - RRFS Servidores v2.1
Apenas root/sistema pode alterar rede.
Usuários sem sudo NÃO conseguem desconectar, trocar rede ou VPN.
CORRIGIDO v2.1:
  - Loop infinito no dispatcher NM
  - Reload excessivo do NetworkManager
  - Wrapper nmcli mais seguro
  - Watchdog não chama _aplicar_protecao_total em loop
  - desconectar_vpn não limpa regras do firewall RRFS
  - Sanitização de senha/SSID no shell
  - Race condition nos tokens
"""

import os
import re
import json
import time
import shutil
import logging
import subprocess
import threading
from pathlib import Path
from datetime import datetime
from threading import Lock, Thread

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Conexao')

PORTA_SISTEMA = 2000
lock = Lock()


def _cmd(comando, timeout=60):
    return executar_comando(comando, timeout=timeout)


def _salvar(path, dados):
    try:
        os.makedirs(os.path.dirname(str(path)), exist_ok=True)
        tmp = str(path) + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
        os.replace(tmp, str(path))
    except Exception as e:
        logger.error(f"salvar {path}: {e}")


def _carregar(path, padrao=None):
    try:
        p = Path(path)
        if p.exists():
            with open(str(p), 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"carregar {path}: {e}")
    return padrao if padrao is not None else {}


def _gerar_id():
    import hashlib
    return hashlib.md5(
        f"{time.time()}{os.urandom(8).hex()}".encode()
    ).hexdigest()[:12]


def _agora():
    return datetime.now().strftime('%d/%m/%Y %H:%M:%S')


def _gerar_mac_aleatorio():
    """MAC aleatório com bit locally administered"""
    import random
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    mac[0] = (mac[0] & 0xfe) | 0x02
    return ':'.join(f'{b:02x}' for b in mac)


def _sanitizar_shell(valor):
    """
    Remove caracteres perigosos para uso em comandos shell.
    Evita injeção de comandos via SSID, senha, etc.
    """
    if not valor:
        return ''
    # Permitir apenas caracteres seguros
    return re.sub(r"[^\w\s\.\-\_\@\!\#\$\%\&\*\(\)\+\=\[\]\{\}\|\:\;\,\?\/]", '', str(valor))


class ConexaoManager:

    def __init__(self, base_dir):
        self.base_dir  = Path(base_dir)
        self.dados_dir = self.base_dir / 'dados' / 'conexao'
        self.vpn_dir   = self.dados_dir / 'vpns'
        self.ovpn_dir  = self.dados_dir / 'ovpn_acesso'

        for d in [self.dados_dir, self.vpn_dir, self.ovpn_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self._cfg_path   = self.dados_dir / 'config.json'
        self._vpns_path  = self.dados_dir / 'vpns.json'
        self._redes_path = self.dados_dir / 'redes_salvas.json'
        self._acc_path   = self.dados_dir / 'vpn_acesso.json'
        self._firewall   = None

        # watchdog thread
        self._watchdog_ativo  = False
        self._watchdog_thread = None

        # controle de proteções já aplicadas
        self._protecoes_aplicadas = False
        self._lock_protecao       = Lock()

        # aplicar todas as proteções
        self._aplicar_protecao_total()

    def set_firewall(self, fw):
        self._firewall = fw

    # ══════════════════════════════════════════════════════
    # PROTEÇÃO TOTAL
    # ══════════════════════════════════════════════════════

    def _aplicar_protecao_total(self):
        """
        Aplica TODAS as camadas de proteção.
        Usa lock para evitar chamadas simultâneas.
        """
        with self._lock_protecao:
            try:
                self._configurar_polkit()
                self._configurar_networkmanager()
                self._instalar_dispatcher_nm()
                self._configurar_sudoers_bloqueio()
                self._bloquear_comandos_rede_usuarios()
                self._protecoes_aplicadas = True
                if not self._watchdog_ativo:
                    self._iniciar_watchdog()
            except Exception as e:
                logger.error(f"_aplicar_protecao_total: {e}")

    def _configurar_polkit(self):
        """
        PolicyKit restritivo:
        - Usuários comuns: NEGADO para TUDO do NetworkManager
        - Root: liberado sem senha
        """
        try:
            polkit_js = """\
// RRFS - Controle total de rede apenas para root
// v2.1 - Gerado automaticamente

polkit.addRule(function(action, subject) {
    if (action.id.indexOf("org.freedesktop.NetworkManager") === 0 ||
        action.id.indexOf("org.freedesktop.network-manager") === 0 ||
        action.id.indexOf("org.freedesktop.nm") === 0) {

        if (subject.user === "root") {
            return polkit.Result.YES;
        }
        return polkit.Result.NO;
    }
});

polkit.addRule(function(action, subject) {
    if (action.id.indexOf("net.openvpn") === 0 ||
        action.id.indexOf("org.freedesktop.openvpn") === 0) {
        if (subject.user === "root") {
            return polkit.Result.YES;
        }
        return polkit.Result.NO;
    }
});
"""
            polkit_dir  = '/etc/polkit-1/rules.d'
            os.makedirs(polkit_dir, exist_ok=True)
            polkit_path = f'{polkit_dir}/00-rrfs-network.rules'

            # Só reescrever se mudou
            if self._arquivo_precisa_atualizar(
                polkit_path, 'v2.1'
            ):
                with open(polkit_path, 'w') as f:
                    f.write(polkit_js)
                os.chmod(polkit_path, 0o644)
                _cmd(
                    'systemctl restart polkit 2>/dev/null',
                    timeout=10
                )

            pkla = """\
[RRFS - Bloquear usuarios comuns]
Identity=unix-user:*
Action=org.freedesktop.NetworkManager.*
ResultAny=no
ResultInactive=no
ResultActive=no

[RRFS - Liberar root]
Identity=unix-user:root
Action=org.freedesktop.NetworkManager.*
ResultAny=yes
ResultInactive=yes
ResultActive=yes
"""
            pkla_dir = '/etc/polkit-1/localauthority/00-system.d'
            os.makedirs(pkla_dir, exist_ok=True)
            pkla_path = f'{pkla_dir}/rrfs-network.pkla'
            if not os.path.exists(pkla_path):
                with open(pkla_path, 'w') as f:
                    f.write(pkla)

        except Exception as e:
            logger.error(f"_configurar_polkit: {e}")

    def _configurar_networkmanager(self):
        """
        NetworkManager configurado para exigir PolicyKit.
        CORRIGIDO: não faz reload desnecessário se já
        está configurado corretamente.
        """
        try:
            nm_conf_dir = '/etc/NetworkManager/conf.d'
            os.makedirs(nm_conf_dir, exist_ok=True)

            conf_seguranca = """\
# RRFS v2.1 - Segurança: apenas root gerencia rede
[main]
auth-polkit=true
no-auto-default=*

[logging]
level=ERR

[connectivity]
enabled=false

[device]
wifi.scan-rand-mac-address=no
"""
            conf_permissoes = """\
# RRFS v2.1 - Permissões de conexão
[connection]
connection.permissions=
"""
            path_seg  = f'{nm_conf_dir}/00-rrfs-security.conf'
            path_perm = f'{nm_conf_dir}/01-rrfs-permissions.conf'

            precisa_reload = False

            if self._arquivo_precisa_atualizar(
                path_seg, 'v2.1'
            ):
                with open(path_seg, 'w') as f:
                    f.write(conf_seguranca)
                precisa_reload = True

            if not os.path.exists(path_perm):
                with open(path_perm, 'w') as f:
                    f.write(conf_permissoes)
                precisa_reload = True

            # Só faz reload se algo mudou
            if precisa_reload:
                _cmd(
                    'systemctl reload NetworkManager 2>/dev/null',
                    timeout=15
                )

        except Exception as e:
            logger.error(f"_configurar_networkmanager: {e}")

    def _instalar_dispatcher_nm(self):
        """
        Instala dispatcher do NetworkManager.
        CORRIGIDO v2.1:
        - Anti-loop com lock file por interface
        - Ignora interfaces de sistema (lo, tun, docker, etc.)
        - Só bloqueia conexões não-RRFS se RRFS tem WAN configurada
        - Cooldown de 30s para evitar loop no bloqueio
        - Verifica se ainda está desconectado antes de reconectar
        - Filtra apenas eventos up/down
        """
        try:
            dispatcher_dir = '/etc/NetworkManager/dispatcher.d'
            os.makedirs(dispatcher_dir, exist_ok=True)

            cfg_path = str(self._cfg_path)
            log_path = str(
                self.dados_dir / 'seguranca_rede.log'
            )

            dispatcher_script = f"""#!/bin/bash
# RRFS - Dispatcher de Segurança de Rede
# v2.1 - CORRIGIDO: loop infinito, interfaces sistema,
#         bloqueio prematuro, cooldown anti-loop

IFACE="$1"
EVENTO="$2"
LOG="{log_path}"
CFG="{cfg_path}"

# ══════════════════════════════════════════════════
# ANTI-LOOP — PRIMEIRA VERIFICAÇÃO
# ══════════════════════════════════════════════════
LOCK="/tmp/rrfs_dispatcher_lock_${{IFACE}}"
if [ -f "$LOCK" ]; then
    exit 0
fi

log_seg() {{
    echo "[$(date '+%d/%m/%Y %H:%M:%S')] $1" >> "$LOG"
}}

# ══════════════════════════════════════════════════
# IGNORAR INTERFACES DE SISTEMA
# ══════════════════════════════════════════════════
case "$IFACE" in
    lo|tun*|tap*|docker*|veth*|br-*|virbr*|dummy*|sit*|ip6tnl*)
        exit 0
        ;;
esac

# ══════════════════════════════════════════════════
# IGNORAR EVENTOS DESNECESSÁRIOS
# ══════════════════════════════════════════════════
case "$EVENTO" in
    up|down)
        ;;
    *)
        exit 0
        ;;
esac

# ══════════════════════════════════════════════════
# CRIAR LOCK — EVITA EXECUÇÃO PARALELA NA MESMA IFACE
# ══════════════════════════════════════════════════
touch "$LOCK"
trap "rm -f '$LOCK'" EXIT

# ══════════════════════════════════════════════════
# EVENTO: DOWN
# ══════════════════════════════════════════════════
if [ "$EVENTO" = "down" ] && [ -f "$CFG" ]; then

    WAN_INFO=$(python3 -c "
import json
try:
    d=json.load(open('$CFG'))
    w=d.get('wan',{{}})
    print(w.get('interface','') + '|' + w.get('nm_conn',''))
except:
    print('|')
" 2>/dev/null)

    WAN_IFACE=$(echo "$WAN_INFO" | cut -d'|' -f1)
    WAN_CONN=$(echo "$WAN_INFO"  | cut -d'|' -f2)

    if [ "$IFACE" = "$WAN_IFACE" ] && [ -n "$WAN_IFACE" ]; then
        RRFS_AUTH="/tmp/rrfs_auth_disconnect_$WAN_IFACE"

        if [ ! -f "$RRFS_AUTH" ]; then
            log_seg "ALERTA: Desconexão NÃO autorizada em $IFACE"
            sleep 3

            # Verificar se ainda está desconectado
            AINDA_DOWN=$(nmcli -t -f DEVICE,STATE dev \\
                2>/dev/null | grep "^${{IFACE}}:" | \\
                grep -v ":activated" | head -1)

            if [ -n "$AINDA_DOWN" ] && [ -n "$WAN_CONN" ]; then
                nmcli con up "$WAN_CONN" 2>/dev/null && \\
                    log_seg "Reconectado em: $WAN_CONN"
            fi
        else
            rm -f "$RRFS_AUTH"
            log_seg "Desconexão autorizada pelo RRFS em $IFACE"
        fi
    fi
fi

# ══════════════════════════════════════════════════
# EVENTO: UP
# ══════════════════════════════════════════════════
if [ "$EVENTO" = "up" ]; then

    CONN_NOME=$(nmcli -t -f NAME,DEVICE con show --active \\
        2>/dev/null | grep ":${{IFACE}}$" | cut -d: -f1 | head -1)

    if [ -z "$CONN_NOME" ]; then
        exit 0
    fi

    # Conexão RRFS: permitir
    if [[ "$CONN_NOME" == rrfs-* ]]; then
        log_seg "Conexão RRFS ativa: $CONN_NOME em $IFACE"
        exit 0
    fi

    # Sem config RRFS: não bloquear
    if [ ! -f "$CFG" ]; then
        exit 0
    fi

    WAN_CONN_CFG=$(python3 -c "
import json
try:
    d=json.load(open('$CFG'))
    print(d.get('wan',{{}}).get('nm_conn',''))
except:
    print('')
" 2>/dev/null)

    # RRFS sem WAN configurada: não bloquear
    if [ -z "$WAN_CONN_CFG" ]; then
        exit 0
    fi

    # Cooldown: não bloquear a mesma conexão por 30s
    BLOCK_LOCK="/tmp/rrfs_blocked_${{CONN_NOME// /_}}"
    if [ -f "$BLOCK_LOCK" ]; then
        exit 0
    fi
    touch "$BLOCK_LOCK"
    ( sleep 30 && rm -f "$BLOCK_LOCK" ) &

    log_seg "ALERTA: Conexão não-RRFS: $CONN_NOME em $IFACE. Bloqueando..."
    nmcli con down "$CONN_NOME" 2>/dev/null
    nmcli con modify "$CONN_NOME" \\
        connection.autoconnect no 2>/dev/null

fi
"""
            disp_path = f'{dispatcher_dir}/99-rrfs-security'

            if self._arquivo_precisa_atualizar(
                disp_path, 'v2.1'
            ):
                with open(disp_path, 'w') as f:
                    f.write(dispatcher_script)
                os.chmod(disp_path, 0o755)
                # Reload apenas se dispatcher mudou
                _cmd(
                    'systemctl reload NetworkManager 2>/dev/null',
                    timeout=15
                )
                logger.error(
                    "Dispatcher atualizado para v2.1"
                )

        except Exception as e:
            logger.error(f"_instalar_dispatcher_nm: {e}")

    def _arquivo_precisa_atualizar(self, path, versao):
        """
        Verifica se arquivo precisa ser atualizado.
        Evita reescritas e reloads desnecessários.
        """
        try:
            if not os.path.exists(path):
                return True
            with open(path, 'r') as f:
                conteudo = f.read()
            return versao not in conteudo
        except Exception:
            return True

    def _configurar_sudoers_bloqueio(self):
        """
        Bloqueia comandos de rede via sudoers.
        """
        try:
            sudoers_content = """\
# RRFS v2.1 - Bloqueio de comandos de rede
Cmnd_Alias RRFS_NETWORK = /usr/bin/nmcli, /sbin/ip, \\
    /usr/sbin/ip, /bin/ip, /sbin/ifconfig, \\
    /usr/bin/ifconfig, /usr/sbin/openvpn, \\
    /usr/bin/openvpn, /sbin/iptables, \\
    /usr/sbin/iptables, /sbin/ufw, /usr/sbin/ufw, \\
    /usr/bin/wpa_supplicant, /sbin/wpa_supplicant, \\
    /usr/sbin/NetworkManager, /usr/bin/nmtui, \\
    /usr/sbin/dhclient, /sbin/dhclient

ALL ALL = !RRFS_NETWORK
"""
            sudoers_path = '/etc/sudoers.d/rrfs-network-block'

            if self._arquivo_precisa_atualizar(
                sudoers_path, 'v2.1'
            ):
                with open(sudoers_path, 'w') as f:
                    f.write(sudoers_content)
                os.chmod(sudoers_path, 0o440)

                r = _cmd(
                    f'visudo -c -f {sudoers_path}', timeout=10
                )
                if not r['sucesso']:
                    os.unlink(sudoers_path)
                    logger.error("sudoers inválido, removido")

        except Exception as e:
            logger.error(f"_configurar_sudoers: {e}")

    def _bloquear_comandos_rede_usuarios(self):
        """
        Wrapper seguro para nmcli.
        CORRIGIDO: verifica se nmcli.real existe e é válido
        antes de substituir. Não substitui se já está correto.
        """
        try:
            _cmd('groupadd -f rrfs-admin 2>/dev/null', timeout=5)

            nmcli_path = '/usr/bin/nmcli'
            nmcli_real = '/usr/bin/nmcli.real'

            # Verificar se wrapper já está instalado e correto
            if os.path.exists(nmcli_path):
                try:
                    with open(nmcli_path, 'r') as f:
                        conteudo = f.read()
                    if 'RRFS' in conteudo and 'v2.1' in conteudo:
                        return  # Já está correto
                except Exception:
                    pass

            wrapper = """\
#!/bin/bash
# RRFS v2.1 - Wrapper de segurança para nmcli

if [ "$(id -u)" != "0" ]; then
    echo "RRFS: Acesso negado. Apenas root pode gerenciar conexões." >&2
    logger -t RRFS-SECURITY "Tentativa bloqueada: $USER tentou usar nmcli"
    exit 1
fi

exec /usr/bin/nmcli.real "$@"
"""
            # Só substitui se nmcli.real não existe ou
            # se o atual não é o wrapper RRFS
            if (os.path.exists(nmcli_path) and
                    not os.path.exists(nmcli_real)):
                shutil.copy2(nmcli_path, nmcli_real)
                with open(nmcli_path, 'w') as f:
                    f.write(wrapper)
                os.chmod(nmcli_path, 0o755)

        except Exception as e:
            logger.error(
                f"_bloquear_comandos_rede_usuarios: {e}"
            )

    # ══════════════════════════════════════════════════════
    # WATCHDOG
    # ══════════════════════════════════════════════════════

    def _iniciar_watchdog(self):
        if self._watchdog_ativo:
            return
        self._watchdog_ativo  = True
        self._watchdog_thread = Thread(
            target=self._watchdog_loop,
            daemon=True,
            name='RRFS-Watchdog'
        )
        self._watchdog_thread.start()

    def _watchdog_loop(self):
        """
        CORRIGIDO v2.1:
        - Não chama _aplicar_protecao_total em loop
        - Apenas verifica se arquivos existem e recria
          individualmente se necessário
        - Contador de falhas por rede antes de tentar outra
        """
        log_seg    = str(self.dados_dir / 'seguranca_rede.log')
        falhas_wan = 0
        falhas_vpn = 0
        MAX_FALHAS_ANTES_TROCAR = 5

        while self._watchdog_ativo:
            try:
                cfg  = _carregar(self._cfg_path, {})
                vpns = _carregar(self._vpns_path, [])

                wan     = cfg.get('wan', {})
                iface   = wan.get('interface', '')
                nm_conn = wan.get('nm_conn', '')

                vpn_ativa = next(
                    (v for v in vpns if v.get('ativa')),
                    None
                )

                # ── verificar WAN ──────────────────────
                if iface and nm_conn:
                    token = (
                        f'/tmp/rrfs_auth_disconnect_{iface}'
                    )
                    conn_ativa = self._conexao_esta_ativa(
                        nm_conn, iface
                    )

                    if not conn_ativa and \
                            not os.path.exists(token):
                        falhas_wan += 1
                        self._registrar_alerta(
                            log_seg,
                            f"WAN {iface} falha "
                            f"{falhas_wan}x (conn: {nm_conn})"
                        )

                        if falhas_wan <= MAX_FALHAS_ANTES_TROCAR:
                            self._restaurar_wan(
                                iface, nm_conn, wan
                            )
                        else:
                            self._registrar_alerta(
                                log_seg,
                                f"Rede atual indisponível após "
                                f"{falhas_wan} tentativas. "
                                f"Buscando alternativa..."
                            )
                            trocou = self._tentar_rede_alternativa(
                                iface, nm_conn
                            )
                            if trocou:
                                falhas_wan = 0
                    else:
                        falhas_wan = 0

                # ── verificar VPN ──────────────────────
                if vpn_ativa:
                    token_vpn = '/tmp/rrfs_auth_disconnect_vpn'
                    tun_ok    = self._tun_esta_ativo()

                    if not tun_ok and \
                            not os.path.exists(token_vpn):
                        falhas_vpn += 1
                        if falhas_vpn >= 2:
                            self._registrar_alerta(
                                log_seg,
                                f"VPN '{vpn_ativa['nome']}' "
                                f"caiu sem autorização. "
                                f"Restaurando..."
                            )
                            self.conectar_vpn(vpn_ativa['id'])
                            falhas_vpn = 0
                    else:
                        falhas_vpn = 0

                # ── verificar proteções ────────────────
                # CORRIGIDO: não chama _aplicar_protecao_total
                # Apenas recria arquivos individualmente
                self._verificar_protecoes()

            except Exception as e:
                logger.error(f"watchdog_loop: {e}")

            time.sleep(15)

    def _verificar_protecoes(self):
        """
        CORRIGIDO v2.1:
        Verifica arquivos de proteção e recria apenas
        o que está faltando, SEM chamar _aplicar_protecao_total
        (que causaria reload do NM em loop).
        """
        try:
            verificacoes = [
                (
                    '/etc/polkit-1/rules.d/00-rrfs-network.rules',
                    self._configurar_polkit
                ),
                (
                    '/etc/NetworkManager/conf.d/00-rrfs-security.conf',
                    self._configurar_networkmanager
                ),
                (
                    '/etc/sudoers.d/rrfs-network-block',
                    self._configurar_sudoers_bloqueio
                ),
                (
                    '/etc/NetworkManager/dispatcher.d/99-rrfs-security',
                    self._instalar_dispatcher_nm
                ),
            ]
            for arq, recriador in verificacoes:
                if not os.path.exists(arq):
                    logger.error(
                        f"Proteção removida: {arq}. Recriando..."
                    )
                    recriador()
        except Exception as e:
            logger.error(f"_verificar_protecoes: {e}")

    def _tentar_rede_alternativa(self, iface_atual, conn_atual):
        try:
            redes = _carregar(self._redes_path, [])
            candidatas = [
                r for r in redes
                if (r.get('interface') == iface_atual and
                    r.get('nm_conn', '') != conn_atual and
                    r.get('tipo') == 'wifi')
            ]
            if not candidatas:
                return False

            r_scan = _cmd(
                f'nmcli -t -f SSID dev wifi list '
                f'ifname {iface_atual} --rescan yes 2>/dev/null',
                timeout=30
            )
            ssids_visiveis = set()
            if r_scan['sucesso']:
                for linha in r_scan['saida'].splitlines():
                    ssid = linha.strip()
                    if ssid:
                        ssids_visiveis.add(ssid)

            for rede in candidatas:
                ssid = rede.get('ssid', '')
                if not ssid or ssid not in ssids_visiveis:
                    continue
                resultado = self.conectar_wifi(rede)
                if resultado.get('sucesso'):
                    return True

            return False
        except Exception as e:
            logger.error(f"_tentar_rede_alternativa: {e}")
            return False

    def _conexao_esta_ativa(self, conn_nome, iface):
        try:
            r = _cmd(
                'nmcli -t -f NAME,DEVICE,STATE '
                'con show --active 2>/dev/null',
                timeout=10
            )
            if r['sucesso']:
                for linha in r['saida'].splitlines():
                    partes = linha.split(':')
                    if (len(partes) >= 3 and
                            partes[1] == iface and
                            'activated' in partes[2]):
                        return True
            return False
        except Exception:
            return False

    def _tun_esta_ativo(self):
        try:
            r = _cmd('ip link show tun0 2>/dev/null', timeout=5)
            return (
                r['sucesso'] and
                'tun0' in r.get('saida', '')
            )
        except Exception:
            return False

    def _restaurar_wan(self, iface, conn_nome, wan_cfg):
        try:
            tipo = wan_cfg.get('tipo', 'ethernet')
            if tipo == 'wifi':
                ssid = wan_cfg.get('ssid_ativo', '')
                if ssid:
                    r_scan = _cmd(
                        f'nmcli -t -f SSID dev wifi list '
                        f'ifname {iface} 2>/dev/null',
                        timeout=15
                    )
                    visivel = False
                    if r_scan['sucesso']:
                        for linha in r_scan['saida'].splitlines():
                            if linha.strip() == ssid:
                                visivel = True
                                break
                    if not visivel:
                        return

            _cmd(
                f'nmcli con up "{conn_nome}" 2>/dev/null',
                timeout=30
            )
        except Exception as e:
            logger.error(f"_restaurar_wan: {e}")

    def _registrar_alerta(self, log_path, msg):
        try:
            with open(log_path, 'a', encoding='utf-8') as f:
                f.write(
                    f"[{_agora()}] ALERTA SEGURANÇA: {msg}\n"
                )
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    # TOKENS DE AUTORIZAÇÃO
    # ══════════════════════════════════════════════════════

    def _criar_token_autorizacao(self, tipo='wan', iface=''):
        """
        CORRIGIDO v2.1: escrita atômica do token.
        """
        try:
            if tipo == 'wan':
                token = f'/tmp/rrfs_auth_disconnect_{iface}'
            elif tipo == 'vpn':
                token = '/tmp/rrfs_auth_disconnect_vpn'
            else:
                token = f'/tmp/rrfs_auth_{tipo}'

            # Escrita atômica
            tmp = token + '.tmp'
            with open(tmp, 'w') as f:
                f.write(str(time.time()))
            os.chmod(tmp, 0o600)
            os.replace(tmp, token)
            return token
        except Exception as e:
            logger.error(f"_criar_token: {e}")
            return ''

    def _remover_token_autorizacao(self, tipo='wan', iface=''):
        try:
            if tipo == 'wan':
                token = f'/tmp/rrfs_auth_disconnect_{iface}'
            elif tipo == 'vpn':
                token = '/tmp/rrfs_auth_disconnect_vpn'
            else:
                token = f'/tmp/rrfs_auth_{tipo}'
            Path(token).unlink(missing_ok=True)
        except Exception:
            pass

    # ══════════════════════════════════════════════════════
    # STATUS GERAL
    # ══════════════════════════════════════════════════════

    def obter_status(self):
        try:
            cfg    = _carregar(self._cfg_path, {})
            vpns   = _carregar(self._vpns_path, [])
            acesso = _carregar(self._acc_path, {})

            vpn_ativa = next(
                (v for v in vpns if v.get('ativa')), None
            )

            tor_r  = _cmd(
                'systemctl is-active tor 2>/dev/null'
            )
            tor_on = (
                tor_r['sucesso'] and
                'active' in tor_r.get('saida', '')
            )

            tun_ip = ''
            r_tun  = _cmd(
                'ip -4 addr show tun0 2>/dev/null'
            )
            if r_tun['sucesso']:
                m = re.search(
                    r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                    r_tun['saida']
                )
                if m:
                    tun_ip = m.group(1)

            wan_cfg = cfg.get('wan', {})

            log_seg = self.dados_dir / 'seguranca_rede.log'
            alertas = 0
            try:
                if log_seg.exists():
                    linhas  = log_seg.read_text().splitlines()
                    alertas = sum(
                        1 for l in linhas[-50:]
                        if 'ALERTA' in l
                    )
            except Exception:
                pass

            return {
                'modo':              cfg.get('modo', 'direto'),
                'modo_nome':         cfg.get('modo_nome', 'Direto'),
                'wan_interface':     wan_cfg.get('interface', 'N/A'),
                'wan_tipo':          wan_cfg.get('tipo', ''),
                'wan_modo_ip':       wan_cfg.get('modo', 'dhcp'),
                'ssid_ativo':        wan_cfg.get('ssid_ativo', ''),
                'mac_atual':         wan_cfg.get('mac_atual', ''),
                'hostname_dhcp':     wan_cfg.get('hostname', ''),
                'vpn_ativa':         vpn_ativa,
                'vpn_tun_ip':        tun_ip,
                'tor_ativo':         tor_on,
                'vpn_acesso_ativa':  acesso.get('ativa', False),
                'vpn_acesso_modo':   acesso.get('modo', ''),
                'total_vpns':        len(vpns),
                'redes_salvas':      len(
                    _carregar(self._redes_path, [])
                ),
                'alertas_seguranca': alertas,
                'watchdog_ativo':    self._watchdog_ativo,
            }
        except Exception as e:
            logger.error(f"obter_status conexao: {e}")
            return {}

    # ══════════════════════════════════════════════════════
    # INTERFACES
    # ══════════════════════════════════════════════════════

    def listar_interfaces(self):
        interfaces = []
        try:
            r = _cmd('ip -o link show')
            if not r['sucesso']:
                return interfaces

            for linha in r['saida'].splitlines():
                m = re.match(r'\d+:\s+(\S+):', linha)
                if not m:
                    continue
                nome = m.group(1)

                skip_fixo = [
                    'lo', 'docker', 'br-', 'veth',
                    'virbr', 'wg'
                ]
                if any(nome.startswith(p) for p in skip_fixo):
                    continue

                eh_tunel = (
                    nome.startswith('tun') or
                    nome.startswith('tap')
                )

                if eh_tunel:
                    estado = 'up' if 'UP' in linha else 'down'
                    if estado != 'up':
                        continue
                    ip_r    = _cmd(f'ip -4 addr show {nome}')
                    ip_addr = ''
                    if ip_r['sucesso']:
                        ip_m = re.search(
                            r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                            ip_r['saida']
                        )
                        if ip_m:
                            ip_addr = ip_m.group(1)
                    interfaces.append({
                        'nome':   nome,
                        'tipo':   'vpn_tunnel',
                        'mac':    '',
                        'ip':     ip_addr,
                        'estado': estado
                    })
                    continue

                sysfs = Path(f'/sys/class/net/{nome}')
                if not sysfs.exists():
                    continue

                tipo = 'wifi' if (
                    (sysfs / 'wireless').exists() or
                    (sysfs / 'phy80211').exists()
                ) else 'ethernet'

                mac = ''
                try:
                    mac = (sysfs / 'address').read_text().strip()
                except Exception:
                    pass

                ip_r    = _cmd(f'ip -4 addr show {nome}')
                ip_addr = ''
                if ip_r['sucesso']:
                    ip_m = re.search(
                        r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                        ip_r['saida']
                    )
                    if ip_m:
                        ip_addr = ip_m.group(1)

                estado = 'up' if 'UP' in linha else 'down'
                interfaces.append({
                    'nome':   nome,
                    'tipo':   tipo,
                    'mac':    mac,
                    'ip':     ip_addr,
                    'estado': estado
                })

        except Exception as e:
            logger.error(f"listar_interfaces: {e}")
        return interfaces

    # ══════════════════════════════════════════════════════
    # REDES SALVAS
    # ══════════════════════════════════════════════════════

    def listar_redes_salvas(self):
        return _carregar(self._redes_path, [])

    def _salvar_rede(self, dados_rede):
        try:
            redes = _carregar(self._redes_path, [])
            chave = (
                f"{dados_rede['interface']}_"
                f"{dados_rede['tipo']}_"
                f"{dados_rede.get('ssid', 'lan')}"
            )
            for i, r in enumerate(redes):
                if r.get('chave') == chave:
                    dados_rede['chave']         = chave
                    dados_rede['atualizado_em'] = _agora()
                    dados_rede['id']            = r.get(
                        'id', _gerar_id()
                    )
                    redes[i] = dados_rede
                    _salvar(self._redes_path, redes)
                    return
            dados_rede['chave']    = chave
            dados_rede['salvo_em'] = _agora()
            dados_rede['id']       = _gerar_id()
            redes.append(dados_rede)
            _salvar(self._redes_path, redes)
        except Exception as e:
            logger.error(f"_salvar_rede: {e}")

    def remover_rede_salva(self, rid):
        try:
            redes        = _carregar(self._redes_path, [])
            rede_remover = next(
                (r for r in redes if r.get('id') == rid), None
            )
            if not rede_remover:
                return {
                    'sucesso': False,
                    'erro': 'Rede não encontrada'
                }

            nm_conn   = rede_remover.get('nm_conn', '')
            interface = rede_remover.get('interface', '')

            cfg        = _carregar(self._cfg_path, {})
            wan_atual  = cfg.get('wan', {})
            conn_atual = wan_atual.get('nm_conn', '')
            era_ativa  = (nm_conn == conn_atual)

            if interface:
                self._criar_token_autorizacao('wan', interface)

            if nm_conn:
                _cmd(
                    f'nmcli con down "{nm_conn}" 2>/dev/null',
                    timeout=15
                )
                time.sleep(1)
                _cmd(
                    f'nmcli con delete "{nm_conn}" 2>/dev/null',
                    timeout=15
                )

            novas = [r for r in redes if r.get('id') != rid]
            _salvar(self._redes_path, novas)

            if era_ativa:
                cfg['wan'] = {}
                _salvar(self._cfg_path, cfg)

            if interface:
                self._remover_token_autorizacao('wan', interface)

            if era_ativa and novas:
                self._conectar_proxima_rede_disponivel(
                    novas, interface
                )

            return {
                'sucesso': True,
                'mensagem': (
                    'Rede removida' +
                    (' e desconectada' if era_ativa else '')
                )
            }
        except Exception as e:
            logger.error(f"remover_rede_salva: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _conectar_proxima_rede_disponivel(self, redes, interface):
        try:
            if not redes:
                return

            candidatas = [
                r for r in redes
                if r.get('interface') == interface
            ]
            if not candidatas:
                candidatas = redes

            r_scan = _cmd(
                f'nmcli -t -f SSID dev wifi list '
                f'ifname {interface} --rescan yes 2>/dev/null',
                timeout=30
            )
            ssids_visiveis = set()
            if r_scan['sucesso']:
                for linha in r_scan['saida'].splitlines():
                    ssid = linha.strip()
                    if ssid:
                        ssids_visiveis.add(ssid)

            for rede in candidatas:
                ssid = rede.get('ssid', '')
                tipo = rede.get('tipo', '')
                if tipo == 'ethernet':
                    self.configurar_wan(rede)
                    return
                if tipo == 'wifi' and ssid in ssids_visiveis:
                    self.conectar_wifi(rede)
                    return

        except Exception as e:
            logger.error(
                f"_conectar_proxima_rede_disponivel: {e}"
            )

    def reconectar_rede(self, rid):
        try:
            redes = _carregar(self._redes_path, [])
            rede  = next(
                (r for r in redes if r.get('id') == rid), None
            )
            if not rede:
                return {
                    'sucesso': False,
                    'erro': 'Rede não encontrada'
                }
            if rede['tipo'] == 'wifi':
                return self.conectar_wifi(rede)
            else:
                return self.configurar_wan(rede)
        except Exception as e:
            logger.error(f"reconectar_rede: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # MAC E HOSTNAME
    # ══════════════════════════════════════════════════════

    def _aplicar_mac_hostname(self, interface, mac='', hostname=''):
        resultado = {
            'mac': mac, 'hostname': hostname,
            'sucesso': True, 'detalhes': []
        }
        try:
            if mac:
                if mac.lower() == 'aleatorio':
                    mac = _gerar_mac_aleatorio()
                    resultado['mac'] = mac

                if not re.match(
                    r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', mac
                ):
                    return {
                        'sucesso': False,
                        'erro': f'MAC inválido: {mac}'
                    }

                _cmd(f'ip link set {interface} down', timeout=10)
                r = _cmd(
                    f'ip link set {interface} address {mac}',
                    timeout=10
                )
                _cmd(f'ip link set {interface} up', timeout=10)
                time.sleep(1)

                if r['sucesso']:
                    resultado['detalhes'].append(f'MAC: {mac}')
                else:
                    r2 = _cmd(
                        f'macchanger -m {mac} {interface} 2>/dev/null',
                        timeout=10
                    )
                    if r2['sucesso']:
                        resultado['detalhes'].append(
                            f'MAC (macchanger): {mac}'
                        )

            if hostname:
                hostname = re.sub(
                    r'[^a-zA-Z0-9\-]', '', hostname
                )[:63]
                if hostname:
                    _cmd(
                        f'nmcli general hostname "{hostname}"',
                        timeout=10
                    )
                    _cmd(
                        f'hostnamectl set-hostname '
                        f'"{hostname}" --transient',
                        timeout=10
                    )
                    resultado['hostname'] = hostname
                    resultado['detalhes'].append(
                        f'Hostname: {hostname}'
                    )

            return resultado
        except Exception as e:
            logger.error(f"_aplicar_mac_hostname: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # WIFI
    # ══════════════════════════════════════════════════════

    def escanear_wifi(self, interface):
        try:
            r = _cmd(
                f'nmcli -t -f SSID,SIGNAL,SECURITY '
                f'dev wifi list ifname {interface} --rescan yes',
                timeout=30
            )
            redes = []
            if r['sucesso']:
                for linha in r['saida'].splitlines():
                    p = linha.split(':')
                    if len(p) >= 2 and p[0]:
                        redes.append({
                            'ssid':      p[0],
                            'sinal':     p[1] if len(p) > 1 else '0',
                            'seguranca': p[2] if len(p) > 2 else 'Aberta'
                        })
                redes.sort(
                    key=lambda x: int(x['sinal'] or '0'),
                    reverse=True
                )
            return redes
        except Exception as e:
            logger.error(f"escanear_wifi: {e}")
            return []

    def conectar_wifi(self, dados):
        """
        CORRIGIDO v2.1:
        - Sanitização de SSID e senha para evitar
          injeção de comandos shell
        - Usa subprocess direto para passar credenciais
          sem expor no shell
        """
        with lock:
            interface = dados.get('interface', '')
            try:
                ssid     = dados.get('ssid', '')
                senha    = dados.get('senha', '')
                modo     = dados.get('modo', 'dhcp')
                mac      = dados.get('mac', '')
                hostname = dados.get('hostname', '')

                if not interface or not ssid:
                    return {
                        'sucesso': False,
                        'erro': 'Interface e SSID obrigatórios'
                    }

                self._criar_token_autorizacao('wan', interface)
                self._bloquear_autoconexao_nm(interface)

                # Scan duplo antes de conectar
                _cmd(
                    f'nmcli dev wifi rescan ifname {interface} 2>/dev/null',
                    timeout=15
                )
                time.sleep(3)

                ssid_encontrado = self._verificar_ssid_visivel(
                    interface, ssid
                )
                if not ssid_encontrado:
                    time.sleep(5)
                    ssid_encontrado = self._verificar_ssid_visivel(
                        interface, ssid
                    )

                if not ssid_encontrado:
                    self._remover_token_autorizacao('wan', interface)
                    return {
                        'sucesso': False,
                        'erro': (
                            f'Rede "{ssid}" não encontrada. '
                            f'Verifique se está no alcance.'
                        )
                    }

                # Desconectar anterior
                cfg_ant  = _carregar(self._cfg_path, {})
                conn_ant = cfg_ant.get('wan', {}).get('nm_conn', '')
                if conn_ant:
                    _cmd(
                        f'nmcli con down "{conn_ant}" 2>/dev/null',
                        timeout=15
                    )

                # Aplicar MAC e hostname
                if mac or hostname:
                    mr = self._aplicar_mac_hostname(
                        interface, mac, hostname
                    )
                    if not mr['sucesso']:
                        self._remover_token_autorizacao(
                            'wan', interface
                        )
                        return mr
                    mac      = mr.get('mac', mac)
                    hostname = mr.get('hostname', hostname)

                conn = (
                    f"rrfs-wifi-"
                    f"{re.sub(r'[^a-zA-Z0-9]', '_', ssid)[:20]}"
                )

                _cmd(
                    f'nmcli con delete "{conn}" 2>/dev/null',
                    timeout=10
                )

                # CORRIGIDO: usar subprocess para não expor
                # senha no shell — evita injeção de comandos
                if senha:
                    cmd_parts = [
                        '/usr/bin/nmcli.real'
                        if os.path.exists('/usr/bin/nmcli.real')
                        else 'nmcli',
                        'dev', 'wifi', 'connect', ssid,
                        'password', senha,
                        'ifname', interface,
                        'name', conn,
                        'hidden', 'no'
                    ]
                else:
                    cmd_parts = [
                        '/usr/bin/nmcli.real'
                        if os.path.exists('/usr/bin/nmcli.real')
                        else 'nmcli',
                        'dev', 'wifi', 'connect', ssid,
                        'ifname', interface,
                        'name', conn,
                        'hidden', 'no'
                    ]

                try:
                    proc = subprocess.run(
                        cmd_parts,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    sucesso_conn = proc.returncode == 0
                    saida_conn   = proc.stdout + proc.stderr
                except subprocess.TimeoutExpired:
                    sucesso_conn = False
                    saida_conn   = 'Timeout na conexão'

                if not sucesso_conn:
                    if ('Secrets were required' in saida_conn or
                            'password' in saida_conn.lower()):
                        self._remover_token_autorizacao(
                            'wan', interface
                        )
                        return {
                            'sucesso': False,
                            'erro': 'Senha incorreta ou necessária'
                        }
                    self._remover_token_autorizacao('wan', interface)
                    return {
                        'sucesso': False,
                        'erro': saida_conn or 'Falha na conexão'
                    }

                # IP fixo pós-conexão
                if modo == 'fixo':
                    ip      = dados.get('ip', '')
                    mascara = dados.get('mascara', '24')
                    gateway = dados.get('gateway', '')
                    dns_srv = dados.get('dns', '8.8.8.8')

                    if not ip:
                        self._remover_token_autorizacao(
                            'wan', interface
                        )
                        return {
                            'sucesso': False,
                            'erro': 'IP obrigatório no modo fixo'
                        }

                    cmd_mod = (
                        f'nmcli con modify "{conn}" '
                        f'ipv4.method manual '
                        f'ipv4.addresses {ip}/{mascara}'
                    )
                    if gateway:
                        cmd_mod += f' ipv4.gateway {gateway}'
                    if dns_srv:
                        cmd_mod += f' ipv4.dns {dns_srv}'
                    _cmd(cmd_mod, timeout=30)
                    _cmd(f'nmcli con up "{conn}"', timeout=30)

                if mac:
                    _cmd(
                        f'nmcli con modify "{conn}" '
                        f'802-11-wireless.cloned-mac-address "{mac}"',
                        timeout=10
                    )
                if hostname:
                    _cmd(
                        f'nmcli con modify "{conn}" '
                        f'ipv4.dhcp-hostname "{hostname}"',
                        timeout=10
                    )

                _cmd(
                    f'nmcli con modify "{conn}" '
                    f'connection.permissions "" '
                    f'connection.autoconnect yes',
                    timeout=10
                )

                r_mac = _cmd(
                    f"ip link show {interface} | "
                    f"grep ether | awk '{{print $2}}'",
                    timeout=5
                )
                mac_atual = (
                    r_mac['saida'].strip()
                    if r_mac['sucesso'] else mac
                )

                self._salvar_rede({
                    'tipo':      'wifi',
                    'interface': interface,
                    'ssid':      ssid,
                    'senha':     senha,
                    'modo':      modo,
                    'ip':        dados.get('ip', ''),
                    'mascara':   dados.get('mascara', '24'),
                    'gateway':   dados.get('gateway', ''),
                    'dns':       dados.get('dns', ''),
                    'mac':       mac,
                    'mac_atual': mac_atual,
                    'hostname':  hostname,
                    'nm_conn':   conn,
                })

                cfg         = _carregar(self._cfg_path, {})
                cfg['wan']  = {
                    'interface':      interface,
                    'tipo':           'wifi',
                    'modo':           modo,
                    'ssid_ativo':     ssid,
                    'mac_atual':      mac_atual,
                    'hostname':       hostname,
                    'nm_conn':        conn,
                    'configurado_em': _agora()
                }
                _salvar(self._cfg_path, cfg)

                self._remover_token_autorizacao('wan', interface)

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'Conectado: {ssid} | MAC: {mac_atual}'
                        + (f' | Host: {hostname}' if hostname else '')
                    ),
                    'mac':      mac_atual,
                    'hostname': hostname
                }
            except Exception as e:
                self._remover_token_autorizacao('wan', interface)
                logger.error(f"conectar_wifi: {e}")
                return {'sucesso': False, 'erro': str(e)}

    def _verificar_ssid_visivel(self, interface, ssid):
        """Verifica se SSID está visível no scan atual"""
        try:
            r = _cmd(
                f'nmcli -t -f SSID dev wifi list '
                f'ifname {interface} 2>/dev/null',
                timeout=15
            )
            if r['sucesso']:
                for linha in r['saida'].splitlines():
                    if linha.strip() == ssid:
                        return True
        except Exception:
            pass
        return False

    def _bloquear_autoconexao_nm(self, interface_rrfs=''):
        try:
            r = _cmd(
                'nmcli -t -f NAME,TYPE con show 2>/dev/null',
                timeout=10
            )
            if not r['sucesso']:
                return
            for linha in r['saida'].splitlines():
                partes = linha.split(':')
                if len(partes) < 2:
                    continue
                nome_conn = partes[0].strip()
                if not nome_conn.startswith('rrfs-'):
                    _cmd(
                        f'nmcli con modify "{nome_conn}" '
                        f'connection.autoconnect no 2>/dev/null',
                        timeout=10
                    )
        except Exception as e:
            logger.error(f"_bloquear_autoconexao_nm: {e}")

    # ══════════════════════════════════════════════════════
    # WAN / ETHERNET
    # ══════════════════════════════════════════════════════

    def configurar_wan(self, dados):
        with lock:
            interface = dados.get('interface', '')
            try:
                tipo     = dados.get('tipo', 'ethernet')
                modo     = dados.get('modo', 'dhcp')
                mac      = dados.get('mac', '')
                hostname = dados.get('hostname', '')

                if not interface:
                    return {
                        'sucesso': False,
                        'erro': 'Interface obrigatória'
                    }

                self._criar_token_autorizacao('wan', interface)

                cfg_ant  = _carregar(self._cfg_path, {})
                conn_ant = cfg_ant.get('wan', {}).get('nm_conn', '')
                if conn_ant:
                    _cmd(
                        f'nmcli con down "{conn_ant}" 2>/dev/null',
                        timeout=15
                    )

                if mac or hostname:
                    mr = self._aplicar_mac_hostname(
                        interface, mac, hostname
                    )
                    if not mr['sucesso']:
                        self._remover_token_autorizacao(
                            'wan', interface
                        )
                        return mr
                    mac      = mr.get('mac', mac)
                    hostname = mr.get('hostname', hostname)

                conn = f'rrfs-wan-{interface}'
                _cmd(
                    f'nmcli con delete "{conn}" 2>/dev/null',
                    timeout=10
                )

                if modo == 'dhcp':
                    _cmd(
                        f'nmcli con add con-name "{conn}" '
                        f'type ethernet ifname {interface} '
                        f'ipv4.method auto',
                        timeout=30
                    )
                elif modo == 'fixo':
                    ip      = dados.get('ip', '')
                    mascara = dados.get('mascara', '24')
                    gateway = dados.get('gateway', '')
                    dns_srv = dados.get('dns', '8.8.8.8')

                    if not ip:
                        self._remover_token_autorizacao(
                            'wan', interface
                        )
                        return {
                            'sucesso': False,
                            'erro': 'IP obrigatório'
                        }

                    cmd = (
                        f'nmcli con add con-name "{conn}" '
                        f'type ethernet ifname {interface} '
                        f'ipv4.method manual '
                        f'ipv4.addresses {ip}/{mascara}'
                    )
                    if gateway:
                        cmd += f' ipv4.gateway {gateway}'
                    if dns_srv:
                        cmd += f' ipv4.dns {dns_srv}'
                    _cmd(cmd, timeout=30)
                else:
                    self._remover_token_autorizacao(
                        'wan', interface
                    )
                    return {
                        'sucesso': False,
                        'erro': f'Modo inválido: {modo}'
                    }

                if mac:
                    _cmd(
                        f'nmcli con modify "{conn}" '
                        f'ethernet.cloned-mac-address "{mac}"',
                        timeout=10
                    )
                if hostname:
                    _cmd(
                        f'nmcli con modify "{conn}" '
                        f'ipv4.dhcp-hostname "{hostname}"',
                        timeout=10
                    )

                _cmd(
                    f'nmcli con modify "{conn}" '
                    f'connection.permissions ""',
                    timeout=10
                )

                r = _cmd(f'nmcli con up "{conn}"', timeout=30)

                r_mac = _cmd(
                    f"ip link show {interface} | "
                    f"grep ether | awk '{{print $2}}'",
                    timeout=5
                )
                mac_atual = (
                    r_mac['saida'].strip()
                    if r_mac['sucesso'] else mac
                )

                self._salvar_rede({
                    'tipo':      'ethernet',
                    'interface': interface,
                    'ssid':      '',
                    'modo':      modo,
                    'ip':        dados.get('ip', ''),
                    'mascara':   dados.get('mascara', '24'),
                    'gateway':   dados.get('gateway', ''),
                    'dns':       dados.get('dns', ''),
                    'mac':       mac,
                    'mac_atual': mac_atual,
                    'hostname':  hostname,
                    'nm_conn':   conn,
                })

                cfg        = _carregar(self._cfg_path, {})
                cfg['wan'] = {
                    'interface':      interface,
                    'tipo':           tipo,
                    'modo':           modo,
                    'mac_atual':      mac_atual,
                    'hostname':       hostname,
                    'nm_conn':        conn,
                    'configurado_em': _agora()
                }
                _salvar(self._cfg_path, cfg)

                self._remover_token_autorizacao('wan', interface)

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'WAN configurada: {interface} '
                        f'| MAC: {mac_atual}'
                        + (f' | Host: {hostname}' if hostname else '')
                    ),
                    'mac':      mac_atual,
                    'hostname': hostname
                }
            except Exception as e:
                self._remover_token_autorizacao('wan', interface)
                logger.error(f"configurar_wan: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # VPNs DE SAÍDA
    # ══════════════════════════════════════════════════════

    def importar_vpn_saida(self, nome, conteudo,
                            usuario='', senha=''):
        try:
            vid    = _gerar_id()
            arq    = self.vpn_dir / f'{vid}.ovpn'
            arq_au = ''

            ip_srv = ''
            porta  = ''
            proto  = 'udp'
            for linha in conteudo.splitlines():
                l = linha.strip()
                if l.startswith('remote '):
                    p = l.split()
                    if len(p) >= 2:
                        ip_srv = p[1]
                    if len(p) >= 3:
                        porta = p[2]
                elif l.startswith('proto '):
                    proto = l.split()[1].lower()
                    proto = 'tcp' if 'tcp' in proto else 'udp'

            if usuario and senha:
                arq_au = str(
                    self.vpn_dir / f'{vid}_auth.txt'
                )
                Path(arq_au).write_text(
                    f'{usuario}\n{senha}\n'
                )
                os.chmod(arq_au, 0o600)

            conteudo_limpo = self._limpar_ovpn(conteudo, arq_au)
            arq.write_text(conteudo_limpo, encoding='utf-8')
            os.chmod(str(arq), 0o600)

            if ip_srv and not re.match(
                r'^\d+\.\d+\.\d+\.\d+$', ip_srv
            ):
                r = _cmd(f'dig +short {ip_srv}', timeout=10)
                if r['sucesso'] and r['saida']:
                    for line in r['saida'].splitlines():
                        if re.match(
                            r'^\d+\.\d+\.\d+\.\d+$', line
                        ):
                            ip_srv = line
                            break

            vpns = _carregar(self._vpns_path, [])
            info = {
                'id':           vid,
                'nome':         nome,
                'arquivo':      str(arq),
                'arquivo_auth': arq_au,
                'ip_servidor':  ip_srv,
                'porta':        porta,
                'protocolo':    proto,
                'usuario':      usuario,
                'portas_saida': ['80', '443'],
                'ativa':        False,
                'importado_em': _agora()
            }
            vpns.append(info)
            _salvar(self._vpns_path, vpns)
            self._criar_regra_vpn_saida(info)

            return {
                'sucesso': True,
                'mensagem': (
                    f'VPN "{nome}" importada. '
                    f'Servidor: {ip_srv}:{porta}'
                )
            }
        except Exception as e:
            logger.error(f"importar_vpn_saida: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _limpar_ovpn(self, conteudo, arq_auth=''):
        linhas = []
        for linha in conteudo.splitlines():
            l = linha.strip()
            if (l.startswith('auth-user-pass') or
                    l.startswith('up ') or
                    l.startswith('down ') or
                    l.startswith('script-security')):
                continue
            linhas.append(linha)
        if arq_auth:
            linhas.append(f'auth-user-pass "{arq_auth}"')
        return '\n'.join(linhas) + '\n'

    def listar_vpns_saida(self):
        return _carregar(self._vpns_path, [])

    def remover_vpn_saida(self, vid):
        try:
            vpns = _carregar(self._vpns_path, [])
            for i, v in enumerate(vpns):
                if v['id'] == vid:
                    if v.get('ativa'):
                        self.desconectar_vpn()
                    self._remover_regra_vpn_saida(v)
                    for a in [
                        v.get('arquivo', ''),
                        v.get('arquivo_auth', '')
                    ]:
                        if a:
                            try:
                                Path(a).unlink(missing_ok=True)
                            except Exception as ex:
                                logger.error(
                                    f"remover arq vpn: {ex}"
                                )
                    nome = v['nome']
                    vpns.pop(i)
                    _salvar(self._vpns_path, vpns)
                    return {
                        'sucesso': True,
                        'mensagem': f'VPN "{nome}" removida'
                    }
            return {'sucesso': False, 'erro': 'Não encontrada'}
        except Exception as e:
            logger.error(f"remover_vpn_saida: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def configurar_portas_saida_vpn(self, vid, portas):
        try:
            vpns = _carregar(self._vpns_path, [])
            for v in vpns:
                if v['id'] == vid:
                    v['portas_saida'] = portas
                    _salvar(self._vpns_path, vpns)
                    self._remover_regra_vpn_saida(v)
                    self._criar_regra_vpn_saida(v)
                    return {
                        'sucesso': True,
                        'mensagem': 'Portas atualizadas'
                    }
            return {
                'sucesso': False,
                'erro': 'VPN não encontrada'
            }
        except Exception as e:
            logger.error(f"configurar_portas_saida_vpn: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # CONECTAR VPN
    # ══════════════════════════════════════════════════════

    def conectar_vpn(self, vid):
        with lock:
            try:
                vpns = _carregar(self._vpns_path, [])
                vpn  = next(
                    (v for v in vpns if v['id'] == vid), None
                )
                if not vpn:
                    return {
                        'sucesso': False,
                        'erro': 'VPN não encontrada'
                    }

                self._criar_token_autorizacao('vpn')
                self._desconectar_vpn_interno()
                time.sleep(2)

                arq = vpn.get('arquivo', '')
                if not arq or not Path(arq).exists():
                    self._remover_token_autorizacao('vpn')
                    return {
                        'sucesso': False,
                        'erro': 'Arquivo VPN não encontrado'
                    }

                conteudo = Path(arq).read_text(encoding='utf-8')
                limpo    = self._limpar_ovpn(
                    conteudo, vpn.get('arquivo_auth', '')
                )
                Path(arq).write_text(limpo, encoding='utf-8')
                os.chmod(arq, 0o600)

                r = _cmd('which openvpn', timeout=5)
                if not r['sucesso']:
                    _cmd(
                        'apt-get install -y openvpn',
                        timeout=180
                    )

                log_f = str(self.dados_dir / 'openvpn.log')
                pid_f = str(self.dados_dir / 'openvpn.pid')
                Path(log_f).write_text('')

                _cmd('killall -9 openvpn 2>/dev/null', timeout=5)
                time.sleep(1)

                arq_path = Path(arq)
                cmd = (
                    f'openvpn '
                    f'--cd {arq_path.parent} '
                    f'--config {arq_path.name} '
                    f'--daemon openvpn-rrfs '
                    f'--log {log_f} '
                    f'--writepid {pid_f} '
                    f'--connect-retry 3 '
                    f'--connect-timeout 30 '
                    f'--disable-dco '
                    f'--verb 3 '
                    f'--script-security 1'
                )

                env         = os.environ.copy()
                env['PATH'] = (
                    '/usr/local/sbin:/usr/local/bin:'
                    '/usr/sbin:/usr/bin:/sbin:/bin'
                )
                subprocess.Popen(
                    cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    start_new_session=True
                )
                time.sleep(4)

                tunnel = False
                for _ in range(30):
                    time.sleep(2)
                    r = _cmd('ip link show tun0', timeout=5)
                    if r['sucesso']:
                        tunnel = True
                        break

                if not tunnel:
                    log_txt = ''
                    try:
                        log_txt = Path(log_f).read_text()
                    except Exception:
                        pass
                    self._desconectar_vpn_interno()
                    self._remover_token_autorizacao('vpn')
                    return {
                        'sucesso': False,
                        'erro': (
                            f'VPN não conectou: {log_txt[-300:]}'
                        )
                    }

                tun_ip = ''
                r = _cmd('ip -4 addr show tun0', timeout=5)
                if r['sucesso']:
                    m = re.search(
                        r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                        r['saida']
                    )
                    if m:
                        tun_ip = m.group(1)

                for v in vpns:
                    v['ativa'] = (v['id'] == vid)
                _salvar(self._vpns_path, vpns)

                cfg = _carregar(self._cfg_path, {})
                wan = cfg.get('wan', {}).get('interface', '')
                if wan:
                    self._aplicar_kill_switch(wan, vpn)

                if self._firewall:
                    try:
                        self._firewall.configurar_vpn_saida_ativa(vpn)
                    except Exception as e:
                        logger.error(
                            f"configurar firewall vpn saida: {e}"
                        )

                self._remover_token_autorizacao('vpn')

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'VPN "{vpn["nome"]}" conectada. '
                        f'IP: {tun_ip}'
                    ),
                    'tun_ip': tun_ip
                }
            except Exception as e:
                self._remover_token_autorizacao('vpn')
                logger.error(f"conectar_vpn: {e}")
                return {'sucesso': False, 'erro': str(e)}

    def desconectar_vpn(self, vid=None):
        """
        CORRIGIDO v2.1:
        - NÃO limpa todas as regras iptables (quebraria
          o firewall RRFS inteiro)
        - Remove apenas regras específicas do kill switch
        - Não afeta openvpn-rrfs-acesso
        """
        try:
            self._criar_token_autorizacao('vpn')

            if self._firewall:
                try:
                    self._firewall.remover_configuracao_vpn('saida')
                except Exception as e:
                    logger.error(
                        f"remover config vpn firewall: {e}"
                    )

            # Matar apenas processo de saída pelo PID
            pid_f = self.dados_dir / 'openvpn.pid'
            if pid_f.exists():
                try:
                    pid = pid_f.read_text().strip()
                    if pid and pid.isdigit():
                        _cmd(f'kill {pid} 2>/dev/null', timeout=5)
                        time.sleep(2)
                        _cmd(
                            f'kill -9 {pid} 2>/dev/null',
                            timeout=5
                        )
                    pid_f.unlink(missing_ok=True)
                except Exception as e:
                    logger.error(f"matar pid vpn: {e}")

            # Matar pelo nome exato — NÃO afeta rrfs-acesso
            _cmd(
                'pkill -f "openvpn-rrfs$" 2>/dev/null',
                timeout=5
            )
            time.sleep(1)
            _cmd(
                'pkill -9 -f "openvpn-rrfs$" 2>/dev/null',
                timeout=5
            )

            # CORRIGIDO: remover apenas regras do kill switch
            # NÃO usar iptables -F (limparia tudo do RRFS)
            self._remover_kill_switch()

            vpns = _carregar(self._vpns_path, [])
            for v in vpns:
                v['ativa'] = False
            _salvar(self._vpns_path, vpns)

            self._remover_token_autorizacao('vpn')

            return {'sucesso': True, 'mensagem': 'VPN desconectada'}
        except Exception as e:
            self._remover_token_autorizacao('vpn')
            logger.error(f"desconectar_vpn: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _desconectar_vpn_interno(self):
        """
        CORRIGIDO v2.1: mata apenas saída, não afeta acesso.
        """
        try:
            pid_f = self.dados_dir / 'openvpn.pid'
            if pid_f.exists():
                try:
                    pid = pid_f.read_text().strip()
                    if pid and pid.isdigit():
                        _cmd(f'kill {pid} 2>/dev/null', timeout=5)
                        time.sleep(2)
                        _cmd(
                            f'kill -9 {pid} 2>/dev/null',
                            timeout=5
                        )
                    pid_f.unlink(missing_ok=True)
                except Exception as e:
                    logger.error(f"pid vpn interno: {e}")

            _cmd(
                'pkill -f "openvpn-rrfs$" 2>/dev/null',
                timeout=5
            )
            time.sleep(1)
            _cmd(
                'pkill -9 -f "openvpn-rrfs$" 2>/dev/null',
                timeout=5
            )

            vpns = _carregar(self._vpns_path, [])
            for v in vpns:
                v['ativa'] = False
            _salvar(self._vpns_path, vpns)

        except Exception as e:
            logger.error(f"desconectar_vpn_interno: {e}")

    # ══════════════════════════════════════════════════════
    # KILL SWITCH
    # ══════════════════════════════════════════════════════

    # Tag para identificar regras do kill switch
    _KS_COMMENT = 'RRFS-KS'

    def _aplicar_kill_switch(self, wan, vpn):
        """
        CORRIGIDO v2.1: usa comentários para identificar
        regras do kill switch e poder removê-las sem
        apagar regras do firewall RRFS.
        """
        try:
            ip    = vpn.get('ip_servidor', '')
            port  = vpn.get('porta', '')
            proto = vpn.get('protocolo', 'udp')

            # Remover kill switch anterior se existia
            self._remover_kill_switch()

            cmds = [
                # Loopback
                f'iptables -A INPUT  -i lo -j ACCEPT -m comment --comment {self._KS_COMMENT}',
                f'iptables -A OUTPUT -o lo -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # Porta RRFS
                f'iptables -A INPUT  -p tcp --dport {PORTA_SISTEMA} -j ACCEPT -m comment --comment {self._KS_COMMENT}',
                f'iptables -A OUTPUT -p tcp --sport {PORTA_SISTEMA} -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # Conexões estabelecidas
                f'iptables -A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment {self._KS_COMMENT}',
                f'iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # Servidor VPN
                f'iptables -A OUTPUT -o {wan} -d {ip} -p {proto} --dport {port} -j ACCEPT -m comment --comment {self._KS_COMMENT}',
                f'iptables -A INPUT  -i {wan} -s {ip} -p {proto} --sport {port} -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # DHCP
                f'iptables -A OUTPUT -o {wan} -p udp --dport 67:68 -j ACCEPT -m comment --comment {self._KS_COMMENT}',
                f'iptables -A INPUT  -i {wan} -p udp --sport 67:68 -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # Túnel VPN
                f'iptables -A OUTPUT -o tun0 -j ACCEPT -m comment --comment {self._KS_COMMENT}',
                f'iptables -A INPUT  -i tun0 -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # Entrada WAN livre (acesso local ao servidor)
                f'iptables -A INPUT -i {wan} -j ACCEPT -m comment --comment {self._KS_COMMENT}',

                # Bloquear saída direta pela WAN
                f'iptables -A OUTPUT -o {wan} -j DROP -m comment --comment {self._KS_COMMENT}',
            ]

            # Interfaces locais adicionais
            try:
                r = _cmd('ip -o link show', timeout=5)
                if r['sucesso']:
                    for linha in r['saida'].splitlines():
                        m = re.match(r'\d+:\s+(\S+):', linha)
                        if not m:
                            continue
                        iface = m.group(1)
                        skip  = [
                            'lo', 'tun', 'tap', 'docker',
                            'br-', 'veth', 'virbr', wan
                        ]
                        if any(
                            iface.startswith(p) for p in skip
                        ):
                            continue
                        if 'UP' not in linha:
                            continue
                        cmds.append(
                            f'iptables -A INPUT  -i {iface} -j ACCEPT '
                            f'-m comment --comment {self._KS_COMMENT}'
                        )
                        cmds.append(
                            f'iptables -A OUTPUT -o {iface} -j ACCEPT '
                            f'-m comment --comment {self._KS_COMMENT}'
                        )
            except Exception as e:
                logger.error(f"kill_switch interfaces: {e}")

            for c in cmds:
                _cmd(c, timeout=10)

        except Exception as e:
            logger.error(f"kill_switch: {e}")

    def _remover_kill_switch(self):
        """
        CORRIGIDO v2.1: remove APENAS regras marcadas
        com o comentário RRFS-KS.
        NÃO usa iptables -F que apagaria tudo.
        """
        try:
            for tabela in ['filter', 'nat']:
                r = _cmd(
                    f'iptables -t {tabela} -S 2>/dev/null',
                    timeout=10
                )
                if not r['sucesso']:
                    continue
                for linha in r['saida'].splitlines():
                    if self._KS_COMMENT in linha:
                        # Converter -A em -D para deletar a regra
                        remover = linha.replace(
                            '-A ', '-D ', 1
                        ).replace(
                            '-I ', '-D ', 1
                        )
                        _cmd(
                            f'iptables -t {tabela} {remover} '
                            f'2>/dev/null',
                            timeout=5
                        )
        except Exception as e:
            logger.error(f"_remover_kill_switch: {e}")

    # ══════════════════════════════════════════════════════
    # MODO CONEXÃO
    # ══════════════════════════════════════════════════════

    def aplicar_modo(self, modo, vpn_id=None):
        try:
            cfg = _carregar(self._cfg_path, {})
            wan = cfg.get('wan', {}).get('interface', '')

            if not wan:
                return {
                    'sucesso': False,
                    'erro': 'Configure a WAN primeiro'
                }

            self._criar_token_autorizacao('vpn')
            self._desconectar_vpn_interno()

            # CORRIGIDO: remover apenas kill switch,
            # não todas as regras iptables
            self._remover_kill_switch()

            # Resetar políticas padrão
            for c in [
                'iptables -P INPUT ACCEPT',
                'iptables -P OUTPUT ACCEPT',
                'iptables -P FORWARD ACCEPT',
            ]:
                _cmd(c, timeout=10)

            self._remover_token_autorizacao('vpn')

            if modo == 'direto':
                if self._firewall:
                    try:
                        self._firewall.remover_configuracao_vpn('todas')
                    except Exception as e:
                        logger.error(
                            f"remover config vpn modo direto: {e}"
                        )
                cfg['modo']      = 'direto'
                cfg['modo_nome'] = 'Direto'
                _salvar(self._cfg_path, cfg)
                return {
                    'sucesso': True,
                    'mensagem': 'Modo direto ativado'
                }

            elif modo in ('vpn', 'vpn_auto'):
                if modo == 'vpn_auto' or not vpn_id:
                    vpn = self._melhor_vpn()
                    if not vpn:
                        return {
                            'sucesso': False,
                            'erro': 'Nenhuma VPN disponível'
                        }
                    vpn_id = vpn['id']
                r = self.conectar_vpn(vpn_id)
                if r['sucesso']:
                    cfg['modo']      = 'vpn'
                    cfg['modo_nome'] = 'VPN'
                    _salvar(self._cfg_path, cfg)
                return r

            return {
                'sucesso': False,
                'erro': f'Modo inválido: {modo}'
            }
        except Exception as e:
            logger.error(f"aplicar_modo: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _melhor_vpn(self):
        vpns   = _carregar(self._vpns_path, [])
        melhor = None
        menor  = 9999
        for v in vpns:
            ip = v.get('ip_servidor', '')
            if not ip:
                continue
            r = _cmd(f'ping -c 2 -W 3 {ip}', timeout=15)
            lat = 9999
            if r['sucesso']:
                m = re.search(
                    r'avg.*?=\s*[\d.]+/([\d.]+)',
                    r['saida']
                )
                if m:
                    lat = float(m.group(1))
            if lat < menor:
                menor  = lat
                melhor = v
        return melhor

    # ══════════════════════════════════════════════════════
    # REGRAS UFW PARA VPN
    # ══════════════════════════════════════════════════════

    def _criar_regra_vpn_saida(self, vpn):
        if not self._firewall:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            nome_pfx = f'VPN:{vpn["nome"]}'
            cfg = _carregar(self._cfg_path, {})
            wan = cfg.get('wan', {}).get('interface', '')
            ip  = vpn.get('ip_servidor', '')
            pt  = vpn.get('porta', '')
            pr  = vpn.get('protocolo', 'udp')

            if ip and pt and wan:
                self._firewall.adicionar_regra_automatica(
                    f'{nome_pfx}:servidor',
                    {
                        'nome':      f'{nome_pfx}:servidor',
                        'interface': wan,
                        'direcao':   'out',
                        'protocolo': pr,
                        'ip':        ip,
                        'porta':     pt
                    },
                    FirewallUFW.CAT_VPN
                )

            for porta in vpn.get('portas_saida', ['80', '443']):
                for proto in ['tcp', 'udp']:
                    self._firewall.adicionar_regra_automatica(
                        f'{nome_pfx}:saida:{porta}:{proto}',
                        {
                            'nome':      f'{nome_pfx}:saida',
                            'interface': 'tun0',
                            'direcao':   'out',
                            'protocolo': proto,
                            'ip':        '',
                            'porta':     porta
                        },
                        FirewallUFW.CAT_VPN
                    )
        except Exception as e:
            logger.error(f"criar_regra_vpn_saida: {e}")

    def _remover_regra_vpn_saida(self, vpn):
        if not self._firewall:
            return
        try:
            self._firewall.remover_regras_vpn(
                f'VPN:{vpn["nome"]}'
            )
        except Exception as e:
            logger.error(f"remover_regra_vpn_saida: {e}")

    # ══════════════════════════════════════════════════════
    # VPN ACESSO
    # ══════════════════════════════════════════════════════

    def configurar_vpn_acesso(self, dados):
        try:
            modo   = dados.get('modo', 'ip_publico')
            portas = dados.get('portas', [])
            if str(PORTA_SISTEMA) not in [str(p) for p in portas]:
                portas.insert(0, str(PORTA_SISTEMA))
            acesso = _carregar(self._acc_path, {})
            acesso.update({
                'modo':           modo,
                'portas':         portas,
                'configurado_em': _agora()
            })
            _salvar(self._acc_path, acesso)
            return {
                'sucesso': True,
                'mensagem': 'VPN de acesso configurada',
                'modo':    modo,
                'portas':  portas
            }
        except Exception as e:
            logger.error(f"configurar_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def status_vpn_acesso(self):
        try:
            acesso  = _carregar(self._acc_path, {})
            r       = _cmd(
                'pgrep -f "openvpn.*rrfs-acesso"', timeout=5
            )
            rodando = r['sucesso'] and bool(r['saida'])
            return {
                'sucesso':             True,
                'ativa':               acesso.get('ativa', False),
                'rodando':             rodando,
                'modo':                acesso.get('modo', ''),
                'portas':              acesso.get('portas', []),
                'ip_publico_servidor': self._ip_publico_servidor(),
                'configurado_em':      acesso.get('configurado_em', '')
            }
        except Exception as e:
            logger.error(f"status_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _ip_publico_servidor(self):
        try:
            r = _cmd(
                'curl -s --max-time 5 https://api.ipify.org',
                timeout=10
            )
            return r['saida'].strip() if r['sucesso'] else 'N/A'
        except Exception as e:
            logger.error(f"_ip_publico: {e}")
            return 'N/A'

    def ativar_vpn_acesso(self):
        try:
            acesso = _carregar(self._acc_path, {})
            modo   = acesso.get('modo', 'ip_publico')
            portas = acesso.get('portas', [str(PORTA_SISTEMA)])

            r = _cmd('which openvpn', timeout=5)
            if not r['sucesso']:
                r2 = _cmd(
                    'apt-get install -y openvpn easy-rsa',
                    timeout=300
                )
                if not r2['sucesso']:
                    return {
                        'sucesso': False,
                        'erro': 'Falha ao instalar OpenVPN'
                    }

            pki_dir = self.ovpn_dir / 'pki'
            srv_cfg = self.ovpn_dir / 'server.conf'

            if not pki_dir.exists():
                if not self._gerar_pki(pki_dir):
                    return {
                        'sucesso': False,
                        'erro': 'Falha ao gerar PKI'
                    }

            ip_publico = self._ip_publico_servidor()
            porta_vpn  = 1194

            if modo == 'tor':
                onion         = self._obter_onion_tor_vpn()
                servidor_addr = onion or ip_publico
            else:
                servidor_addr = ip_publico

            self._gerar_config_servidor(
                srv_cfg, pki_dir, porta_vpn, portas
            )

            log_f = str(self.ovpn_dir / 'server.log')
            pid_f = str(self.ovpn_dir / 'server.pid')

            _cmd(
                'pkill -f "openvpn.*rrfs-acesso"', timeout=5
            )
            time.sleep(1)

            cmd = (
                f'openvpn --config {srv_cfg} '
                f'--daemon openvpn-rrfs-acesso '
                f'--log {log_f} --writepid {pid_f}'
            )
            _cmd(cmd, timeout=30)
            time.sleep(3)

            r_pid = _cmd(
                'pgrep -f "openvpn-rrfs-acesso"', timeout=5
            )
            if not r_pid['sucesso']:
                log_txt = ''
                try:
                    log_txt = Path(log_f).read_text()
                except Exception:
                    pass
                return {
                    'sucesso': False,
                    'erro': (
                        f'Servidor não iniciou: {log_txt[-300:]}'
                    )
                }

            if self._firewall:
                from modulos.firewall_ufw import FirewallUFW
                time.sleep(3)
                try:
                    self._firewall.configurar_vpn_acesso_ativa({
                        'portas':    portas,
                        'porta_vpn': porta_vpn
                    })
                except Exception as e:
                    logger.error(
                        f"configurar firewall vpn acesso: {e}"
                    )

                self._firewall.adicionar_regra_automatica(
                    'VPNAcesso:porta_vpn',
                    {
                        'nome':      'VPN Acesso: OpenVPN',
                        'interface': '',
                        'direcao':   'in',
                        'protocolo': 'udp',
                        'ip':        '',
                        'porta':     str(porta_vpn)
                    },
                    FirewallUFW.CAT_VPN
                )
                for porta in portas:
                    self._firewall.adicionar_regra_automatica(
                        f'VPNAcesso:p{porta}',
                        {
                            'nome':      f'VPN Acesso: {porta}',
                            'interface': '',
                            'direcao':   'in',
                            'protocolo': 'tcp',
                            'ip':        '',
                            'porta':     str(porta)
                        },
                        FirewallUFW.CAT_VPN
                    )

            acesso.update({
                'ativa':         True,
                'porta_vpn':     porta_vpn,
                'ip_publico':    ip_publico,
                'servidor_addr': servidor_addr,
                'ativado_em':    _agora()
            })
            _salvar(self._acc_path, acesso)

            return {
                'sucesso':       True,
                'mensagem':      'Servidor VPN de acesso ativado!',
                'servidor_addr': servidor_addr,
                'porta_vpn':     porta_vpn,
                'modo':          modo
            }
        except Exception as e:
            logger.error(f"ativar_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def desativar_vpn_acesso(self):
        try:
            _cmd('pkill -f "openvpn-rrfs-acesso"', timeout=5)
            time.sleep(1)
            _cmd(
                'pkill -9 -f "openvpn-rrfs-acesso"', timeout=5
            )

            if self._firewall:
                try:
                    self._firewall.remover_configuracao_vpn('acesso')
                    self._firewall.remover_regras_vpn('VPNAcesso:')
                except Exception as e:
                    logger.error(
                        f"remover config vpn acesso fw: {e}"
                    )

            acesso          = _carregar(self._acc_path, {})
            acesso['ativa'] = False
            _salvar(self._acc_path, acesso)

            return {
                'sucesso': True,
                'mensagem': 'Servidor VPN desativado'
            }
        except Exception as e:
            logger.error(f"desativar_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _gerar_pki(self, pki_dir):
        try:
            pki_dir.mkdir(parents=True, exist_ok=True)
            passos = [
                (f'openssl genrsa -out {pki_dir}/ca.key 4096', 60),
                (f'openssl req -new -x509 -days 3650 '
                 f'-key {pki_dir}/ca.key '
                 f'-out {pki_dir}/ca.crt '
                 f'-subj "/CN=RRFS-CA"', 60),
                (f'openssl genrsa -out {pki_dir}/server.key 4096', 60),
                (f'openssl req -new '
                 f'-key {pki_dir}/server.key '
                 f'-out {pki_dir}/server.csr '
                 f'-subj "/CN=RRFS-Server"', 30),
                (f'openssl x509 -req -days 3650 '
                 f'-in {pki_dir}/server.csr '
                 f'-CA {pki_dir}/ca.crt '
                 f'-CAkey {pki_dir}/ca.key '
                 f'-CAcreateserial '
                 f'-out {pki_dir}/server.crt', 60),
                (f'openssl genrsa -out {pki_dir}/client.key 4096', 60),
                (f'openssl req -new '
                 f'-key {pki_dir}/client.key '
                 f'-out {pki_dir}/client.csr '
                 f'-subj "/CN=RRFS-Client"', 30),
                (f'openssl x509 -req -days 3650 '
                 f'-in {pki_dir}/client.csr '
                 f'-CA {pki_dir}/ca.crt '
                 f'-CAkey {pki_dir}/ca.key '
                 f'-CAcreateserial '
                 f'-out {pki_dir}/client.crt', 60),
                (f'openssl dhparam -out {pki_dir}/dh.pem 2048', 180),
                (f'openvpn --genkey secret {pki_dir}/ta.key', 30),
            ]
            for cmd, timeout in passos:
                _cmd(cmd, timeout=timeout)
            return True
        except Exception as e:
            logger.error(f"gerar_pki: {e}")
            return False

    def _gerar_config_servidor(self, cfg_path, pki_dir,
                                porta, portas_acesso):
        try:
            conteudo = f"""# RRFS - Servidor VPN de Acesso
port {porta}
proto udp
dev tun
ca {pki_dir}/ca.crt
cert {pki_dir}/server.crt
key {pki_dir}/server.key
dh {pki_dir}/dh.pem
tls-auth {pki_dir}/ta.key 0
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /tmp/ipp.txt
keepalive 10 120
cipher AES-256-GCM
persist-key
persist-tun
verb 3
push "route 10.8.0.1 255.255.255.255"
"""
            Path(cfg_path).write_text(conteudo)
            os.chmod(str(cfg_path), 0o600)
        except Exception as e:
            logger.error(f"gerar_config_servidor: {e}")

    def gerar_ovpn_acesso(self):
        try:
            acesso  = _carregar(self._acc_path, {})
            pki_dir = self.ovpn_dir / 'pki'

            if not pki_dir.exists():
                return {
                    'sucesso': False,
                    'erro': 'PKI não gerada. Ative a VPN primeiro.'
                }

            modo      = acesso.get('modo', 'ip_publico')
            porta_vpn = acesso.get('porta_vpn', 1194)

            if modo == 'tor':
                addr = acesso.get('servidor_addr', '')
                if not addr or '.onion' not in addr:
                    return {
                        'sucesso': False,
                        'erro': 'Endereço .onion não disponível'
                    }
                remote_line = (
                    f'remote {addr} {porta_vpn}\n'
                    f'socks-proxy 127.0.0.1 9050\n'
                )
            else:
                ip = acesso.get('ip_publico', '')
                if not ip or ip == 'N/A':
                    return {
                        'sucesso': False,
                        'erro': 'IP público não disponível'
                    }
                remote_line = f'remote {ip} {porta_vpn}\n'

            def ler(nome):
                p = pki_dir / nome
                return p.read_text() if p.exists() else ''

            ovpn = f"""client
dev tun
proto udp
{remote_line}resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
verb 3
key-direction 1
<ca>
{ler('ca.crt')}</ca>
<cert>
{ler('client.crt')}</cert>
<key>
{ler('client.key')}</key>
<tls-auth>
{ler('ta.key')}</tls-auth>
"""
            ovpn_path = self.ovpn_dir / 'cliente.ovpn'
            ovpn_path.write_text(ovpn)
            os.chmod(str(ovpn_path), 0o600)

            return {'sucesso': True, 'arquivo': str(ovpn_path)}
        except Exception as e:
            logger.error(f"gerar_ovpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _obter_onion_tor_vpn(self):
        try:
            from modulos.tor_manager import TorManager
            tor = TorManager(str(self.base_dir))
            for s in tor.config.get('servicos', []):
                if ('vpn' in s.get('nome', '').lower() or
                        s.get('porta_destino') == 1194):
                    onion = tor._ler_onion(s.get('dir_id', ''))
                    if onion:
                        return onion
        except Exception as e:
            logger.error(f"obter_onion_tor_vpn: {e}")
        return ''

    # ══════════════════════════════════════════════════════
    # ALERTAS DE SEGURANÇA
    # ══════════════════════════════════════════════════════

    def obter_alertas_seguranca(self):
        try:
            log_seg = self.dados_dir / 'seguranca_rede.log'
            if not log_seg.exists():
                return []
            linhas  = log_seg.read_text().splitlines()
            alertas = [l for l in linhas[-100:] if 'ALERTA' in l]
            return list(reversed(alertas))
        except Exception as e:
            logger.error(f"obter_alertas: {e}")
            return []

    def limpar_alertas_seguranca(self):
        try:
            log_seg = self.dados_dir / 'seguranca_rede.log'
            log_seg.write_text('')
            return {'sucesso': True, 'mensagem': 'Alertas limpos'}
        except Exception as e:
            logger.error(f"limpar_alertas: {e}")
            return {'sucesso': False, 'erro': str(e)}
