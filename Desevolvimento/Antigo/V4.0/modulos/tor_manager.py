#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tor_manager.py - RRFS Servidores
Integrado com conexao.py:
- Detecta interface correta (WAN ou tun0 de VPN de saída)
- Nunca confunde VPN de saída com VPN de acesso
- Regras UFW vinculadas à interface real de saída
- CORRIGIDO: Saída irrestrita para bootstrap funcionar
- CORRIGIDO v2.4: Regras LAN para serviços com IP customizado
"""

import os
import re
import json
import time
import shutil
import logging
import hashlib
import threading
from datetime import datetime

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Tor')

TOR_PORTAS_SAIDA = [
    {'porta': '9001', 'proto': 'tcp', 'desc': 'OR port'},
    {'porta': '9030', 'proto': 'tcp', 'desc': 'Dir port'},
    {'porta': '443',  'proto': 'tcp', 'desc': 'HTTPS'},
    {'porta': '80',   'proto': 'tcp', 'desc': 'HTTP'},
    {'porta': '53',   'proto': 'udp', 'desc': 'DNS'},
]

TOR_PORTAS_LOCAL = [
    {'porta': '9050', 'proto': 'tcp', 'desc': 'SOCKS'},
    {'porta': '9051', 'proto': 'tcp', 'desc': 'Control'},
]


class TorManager:

    def __init__(self, base_dir):
        self.base_dir      = base_dir
        self.config_path   = os.path.join(
            base_dir, 'dados', 'tor_config.json'
        )
        self.torrc_path    = '/etc/tor/torrc'
        self.hs_dir        = '/var/lib/tor'
        self.config        = self._carregar()
        self._firewall_ufw = None
        self._polling: dict = {}
        self._fw_lock      = threading.Lock()

        self._cfg_conexao = os.path.join(
            base_dir, 'dados', 'conexao', 'config.json'
        )
        self._vpns_path   = os.path.join(
            base_dir, 'dados', 'conexao', 'vpns.json'
        )
        self._acc_path    = os.path.join(
            base_dir, 'dados', 'conexao', 'vpn_acesso.json'
        )

    def set_firewall_ufw(self, fw):
        with self._fw_lock:
            self._firewall_ufw = fw
        if self.config.get('ativo') and fw:
            t = threading.Thread(
                target=self._garantir_regras_ufw_tor,
                daemon=True,
                name='Tor-FW-Init'
            )
            t.start()

    # ══════════════════════════════════════════════════════
    # DETECÇÃO DE INTERFACE
    # ══════════════════════════════════════════════════════

    def _obter_info_saida(self):
        resultado = {
            'interface_saida': '',
            'interface_wan':   '',
            'via_vpn':         False,
            'vpn_nome':        '',
            'tun_saida':       '',
        }
        try:
            wan_fisica = self._ler_wan_fisica()
            resultado['interface_wan'] = wan_fisica

            vpn_saida = self._ler_vpn_saida_ativa()

            if vpn_saida:
                tun = self._descobrir_tun_vpn_saida(vpn_saida)
                if tun:
                    resultado['via_vpn']        = True
                    resultado['vpn_nome']        = vpn_saida.get('nome', '')
                    resultado['tun_saida']       = tun
                    resultado['interface_saida'] = tun
                    return resultado

            if wan_fisica:
                resultado['interface_saida'] = wan_fisica
            else:
                resultado['interface_saida'] = (
                    self._rota_default_iface()
                )
        except Exception as e:
            logger.error(f"_obter_info_saida: {e}")
        return resultado

    def _ler_wan_fisica(self):
        try:
            if os.path.exists(self._cfg_conexao):
                with open(self._cfg_conexao, 'r') as f:
                    cfg = json.load(f)
                iface = cfg.get('wan', {}).get('interface', '')
                if iface:
                    return iface
        except Exception as e:
            logger.error(f"_ler_wan_fisica: {e}")
        return ''

    def _ler_vpn_saida_ativa(self):
        try:
            if os.path.exists(self._vpns_path):
                with open(self._vpns_path, 'r') as f:
                    vpns = json.load(f)
                for v in vpns:
                    if v.get('ativa', False):
                        return v
        except Exception as e:
            logger.error(f"_ler_vpn_saida_ativa: {e}")
        return None

    def _descobrir_tun_vpn_saida(self, vpn):
        try:
            tun_acesso = self._tun_da_vpn_acesso()
            r = executar_comando(
                'ip -o link show | '
                "grep -E 'tun[0-9]+' | "
                "awk -F': ' '{print $2}' | "
                "awk '{print $1}'",
                timeout=10
            )
            tuns_ativas = []
            if r['sucesso'] and r['saida'].strip():
                for t in r['saida'].splitlines():
                    t = t.strip()
                    if t and t != tun_acesso:
                        tuns_ativas.append(t)
            if not tuns_ativas:
                return ''
            if 'tun0' in tuns_ativas:
                return 'tun0'
            return tuns_ativas[0]
        except Exception as e:
            logger.error(f"_descobrir_tun_vpn_saida: {e}")
        return 'tun0'

    def _tun_da_vpn_acesso(self):
        try:
            if os.path.exists(self._acc_path):
                with open(self._acc_path, 'r') as f:
                    acesso = json.load(f)
                if not acesso.get('ativa', False):
                    return ''
            r = executar_comando(
                'pgrep -f "openvpn-rrfs-acesso" | head -1',
                timeout=5
            )
            if not r['sucesso'] or not r['saida'].strip():
                return ''
            pid = r['saida'].strip()
            r2 = executar_comando(
                f'ls -la /proc/{pid}/fd 2>/dev/null | grep tun',
                timeout=5
            )
            if r2['sucesso'] and r2['saida']:
                m = re.search(r'tun(\d+)', r2['saida'])
                if m:
                    return f'tun{m.group(1)}'
            r3 = executar_comando(
                'ip route show 10.8.0.0/24 2>/dev/null | '
                "awk '{print $3}'",
                timeout=5
            )
            if r3['sucesso'] and r3['saida'].strip():
                iface = r3['saida'].strip()
                if iface.startswith('tun'):
                    return iface
        except Exception as e:
            logger.error(f"_tun_da_vpn_acesso: {e}")
        return ''

    def _rota_default_iface(self):
        try:
            r = executar_comando(
                'ip route show default 2>/dev/null | '
                "awk '/default/ {print $5}' | head -1",
                timeout=10
            )
            if r['sucesso'] and r['saida'].strip():
                iface = r['saida'].strip()
                if not iface.startswith('tun'):
                    return iface
        except Exception as e:
            logger.error(f"_rota_default_iface: {e}")
        return ''

    # ══════════════════════════════════════════════════════
    # CONFIG
    # ══════════════════════════════════════════════════════

    def _carregar(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r',
                          encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"tor carregar: {e}")
        return {'ativo': False, 'servicos': []}

    def _salvar(self):
        try:
            os.makedirs(
                os.path.dirname(self.config_path),
                exist_ok=True
            )
            with open(self.config_path, 'w',
                      encoding='utf-8') as f:
                json.dump(self.config, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"tor salvar: {e}")

    def _gerar_id(self):
        raw = (f"{datetime.now().isoformat()}"
               f"{os.urandom(16).hex()}")
        return 'hs_' + hashlib.sha256(
            raw.encode()
        ).hexdigest()[:12]

    # ══════════════════════════════════════════════════════
    # STATUS
    # ══════════════════════════════════════════════════════

    def obter_status(self):
        try:
            instalado = self._instalado()
            ativo     = False
            bootstrap = 0

            if instalado:
                for servico in ['tor@default', 'tor']:
                    r = executar_comando(
                        f'systemctl is-active {servico} '
                        f'2>/dev/null'
                    )
                    if (r['sucesso'] and
                            'active' in r.get('saida', '') and
                            'inactive' not in r.get('saida', '')):
                        ativo = True
                        break
                if ativo:
                    bootstrap = self._obter_bootstrap()

            servicos   = self._servicos_com_onion()
            info_saida = self._obter_info_saida()

            fw_ok     = self._verificar_regras_fw()
            problemas = []
            if self._firewall_ufw:
                problemas = (
                    self._firewall_ufw.diagnosticar_regras_tor()
                )

            return {
                'instalado':          instalado,
                'servico_ativo':      ativo,
                'ativo':              self.config.get('ativo', False),
                'bootstrap':          bootstrap,
                'servicos':           servicos,
                'total':              len(servicos),
                'fw_ok':              fw_ok,
                'fw_problemas':       problemas,
                'interface_saida':    info_saida['interface_saida'],
                'interface_wan':      info_saida['interface_wan'],
                'via_vpn':            info_saida['via_vpn'],
                'vpn_nome':           info_saida['vpn_nome'],
                'tun_saida':          info_saida['tun_saida'],
                'log_recente':        self._obter_log_tor(15),
            }
        except Exception as e:
            logger.error(f"tor obter_status: {e}")
            return {
                'instalado': False, 'servico_ativo': False,
                'ativo': False, 'bootstrap': 0,
                'servicos': [], 'total': 0,
                'fw_ok': False, 'fw_problemas': [],
                'interface_saida': '', 'interface_wan': '',
                'via_vpn': False, 'vpn_nome': '',
                'tun_saida': '', 'log_recente': ''
            }

    def obter_status_resumido(self):
        try:
            r = executar_comando(
                'systemctl is-active tor 2>/dev/null'
            )
            ativo = (r['sucesso'] and
                     'active' in r.get('saida', ''))
            return {
                'servico_ativo': ativo,
                'ativo':         self.config.get('ativo', False),
                'servicos':      self._servicos_com_onion(),
                'total':         len(
                    self.config.get('servicos', [])
                ),
            }
        except Exception as e:
            logger.error(f"tor resumido: {e}")
            return {
                'servico_ativo': False, 'ativo': False,
                'servicos': [], 'total': 0
            }

    def _instalado(self):
        r = executar_comando('which tor 2>/dev/null')
        return r['sucesso'] and bool(r.get('saida', '').strip())

    def _obter_bootstrap(self):
        try:
            for servico in ['tor@default', 'tor']:
                r = executar_comando(
                    f'journalctl -u {servico} '
                    f'--since "30 minutes ago" '
                    f'--no-pager -q 2>/dev/null | '
                    f'grep -i "bootstrapped" | tail -5',
                    timeout=15
                )
                if r['sucesso'] and r['saida']:
                    for l in reversed(r['saida'].splitlines()):
                        m = re.search(
                            r'Bootstrapped\s+(\d+)%', l, re.I
                        )
                        if m:
                            return int(m.group(1))
            for lp in [
                '/var/log/tor/log',
                '/var/log/tor/notices.log',
            ]:
                if not os.path.exists(lp):
                    continue
                r2 = executar_comando(
                    f'grep -i "bootstrapped" {lp} 2>/dev/null'
                    f' | tail -5',
                    timeout=10
                )
                if r2['sucesso'] and r2['saida']:
                    for l in reversed(r2['saida'].splitlines()):
                        m = re.search(
                            r'Bootstrapped\s+(\d+)%', l, re.I
                        )
                        if m:
                            return int(m.group(1))
        except Exception as e:
            logger.error(f"_obter_bootstrap: {e}")
        return 0

    def _obter_log_tor(self, linhas=15):
        try:
            for servico in ['tor@default', 'tor']:
                r = executar_comando(
                    f'journalctl -u {servico} '
                    f'--since "10 minutes ago" '
                    f'--no-pager -q 2>/dev/null | tail -{linhas}',
                    timeout=10
                )
                if r['sucesso'] and r['saida']:
                    return r['saida']
            for lp in ['/var/log/tor/log',
                       '/var/log/tor/notices.log']:
                if os.path.exists(lp):
                    r2 = executar_comando(
                        f'tail -{linhas} {lp} 2>/dev/null',
                        timeout=5
                    )
                    if r2['sucesso']:
                        return r2['saida']
        except Exception as e:
            logger.error(f"_obter_log_tor: {e}")
        return ''

    def _verificar_regras_fw(self):
        if not self._firewall_ufw:
            return False
        try:
            return len(
                self._firewall_ufw.diagnosticar_regras_tor()
            ) == 0
        except Exception:
            return False

    def _servicos_com_onion(self):
        result = []
        for s in self.config.get('servicos', []):
            sc          = dict(s)
            dir_id      = s.get('dir_id', '')
            sc['onion'] = self._ler_onion(dir_id)
            sc['gerando'] = (
                dir_id in self._polling and
                self._polling[dir_id].is_alive() and
                not sc['onion']
            )
            result.append(sc)
        return result

    def _ler_onion(self, dir_id):
        if not dir_id:
            return ''
        path = os.path.join(
            self.hs_dir,
            f'hidden_service_{dir_id}',
            'hostname'
        )
        try:
            if os.path.exists(path):
                with open(path, 'r') as f:
                    v = f.read().strip()
                    if v:
                        return v
        except PermissionError:
            pass
        except Exception as e:
            logger.error(f"ler_onion: {e}")
        r = executar_comando(f'cat {path} 2>/dev/null')
        if r['sucesso'] and r['saida'].strip():
            return r['saida'].strip()
        return ''

    # ══════════════════════════════════════════════════════
    # ATIVAR / DESATIVAR
    # ══════════════════════════════════════════════════════

    def ativar(self):
        try:
            if not self._instalado():
                r = executar_comando(
                    'apt-get install -y tor', timeout=300
                )
                if not r['sucesso']:
                    return {
                        'sucesso': False,
                        'erro': 'Falha ao instalar Tor'
                    }

            info        = self._obter_info_saida()
            iface_saida = info['interface_saida']
            via_vpn     = info['via_vpn']
            vpn_nome    = info['vpn_nome']

            r_fw = self._garantir_regras_ufw_tor(info)
            self._corrigir_permissoes_todos()
            self._gerar_torrc()

            r_v = executar_comando(
                'tor --verify-config 2>&1', timeout=15
            )
            saida_v = r_v.get('saida', '')
            if ('err' in saida_v.lower() and
                    'Configuration was valid' not in saida_v):
                return {
                    'sucesso': False,
                    'erro': f'Config inválida: {saida_v[-300:]}'
                }

            executar_comando(
                'systemctl enable tor@default', timeout=10
            )
            r = executar_comando(
                'systemctl restart tor@default', timeout=30
            )
            if not r['sucesso']:
                r = executar_comando(
                    'systemctl restart tor', timeout=30
                )

            time.sleep(2)
            r_st = executar_comando(
                'systemctl is-active tor@default 2>/dev/null',
                timeout=5
            )
            if not (r_st['sucesso'] and
                    'active' in r_st.get('saida', '')):
                log = self._obter_log_tor(30)
                return {
                    'sucesso': False,
                    'erro': f'Tor não iniciou: {log[-300:]}'
                }

            self.config['ativo'] = True
            self._salvar()

            t = threading.Thread(
                target=self._poll_bootstrap_loop,
                daemon=True,
                name='Tor-Bootstrap'
            )
            t.start()

            msg = 'Tor ativado!'
            if via_vpn:
                msg += (
                    f' Saída via VPN ({vpn_nome})'
                    f' → {iface_saida}'
                )
            else:
                msg += f' Saída via WAN → {iface_saida}'
            msg += '. Aguardando bootstrap...'

            return {
                'sucesso':         True,
                'mensagem':        msg,
                'fw_configurado':  r_fw,
                'interface_saida': iface_saida,
                'via_vpn':         via_vpn,
                'vpn_nome':        vpn_nome,
            }
        except Exception as e:
            logger.error(f"tor ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def desativar(self):
        try:
            executar_comando(
                'systemctl stop tor@default 2>/dev/null',
                timeout=30
            )
            executar_comando(
                'systemctl stop tor 2>/dev/null',
                timeout=10
            )
            executar_comando(
                'systemctl disable tor@default 2>/dev/null',
                timeout=10
            )
            self._remover_regras_ufw_tor_infra()
            self.config['ativo'] = False
            self._salvar()
            return {'sucesso': True, 'mensagem': 'Tor desativado'}
        except Exception as e:
            logger.error(f"tor desativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def reparar_firewall(self):
        try:
            info = self._obter_info_saida()
            ok   = self._garantir_regras_ufw_tor(info)
            if not ok:
                return {
                    'sucesso': False,
                    'erro': 'Firewall não disponível'
                }
            prob = self._firewall_ufw.diagnosticar_regras_tor()
            return {
                'sucesso':         True,
                'mensagem':        'Regras recriadas com sucesso!',
                'problemas':       prob,
                'interface_saida': info['interface_saida'],
                'via_vpn':         info['via_vpn'],
                'vpn_nome':        info['vpn_nome'],
            }
        except Exception as e:
            logger.error(f"reparar_firewall: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def obter_diagnostico(self):
        try:
            info      = self._obter_info_saida()
            bootstrap = self._obter_bootstrap()
            log       = self._obter_log_tor(30)

            r_v = executar_comando(
                'tor --verify-config 2>&1', timeout=15
            )
            torrc_ok  = (
                'Configuration was valid' in
                r_v.get('saida', '')
            )
            torrc_txt = ''
            try:
                if os.path.exists(self.torrc_path):
                    with open(self.torrc_path, 'r') as f:
                        torrc_txt = f.read()
            except Exception:
                pass

            conectividade = {}
            for porta in ['443', '80', '9001']:
                r_nc = executar_comando(
                    f'timeout 5 nc -z -w 3 '
                    f'check.torproject.org {porta} '
                    f'2>/dev/null && echo OK || echo FAIL',
                    timeout=10
                )
                conectividade[porta] = (
                    'OK' in r_nc.get('saida', '')
                )

            prob = []
            if self._firewall_ufw:
                prob = (
                    self._firewall_ufw.diagnosticar_regras_tor()
                )

            return {
                'sucesso':         True,
                'bootstrap':       bootstrap,
                'log':             log,
                'interface_saida': info['interface_saida'],
                'interface_wan':   info['interface_wan'],
                'via_vpn':         info['via_vpn'],
                'vpn_nome':        info['vpn_nome'],
                'tun_saida':       info['tun_saida'],
                'torrc_ok':        torrc_ok,
                'torrc_conteudo':  torrc_txt,
                'conectividade':   conectividade,
                'fw_problemas':    prob,
            }
        except Exception as e:
            logger.error(f"obter_diagnostico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # REGRAS UFW — INFRAESTRUTURA TOR
    # ══════════════════════════════════════════════════════

    def _garantir_regras_ufw_tor(self, info_saida=None):
        with self._fw_lock:
            fw = self._firewall_ufw
        if not fw:
            logger.error("_garantir_regras_ufw_tor: fw None")
            return False

        if info_saida is None:
            info_saida = self._obter_info_saida()

        iface_saida = info_saida.get('interface_saida', '')

        try:
            from modulos.firewall_ufw import FirewallUFW

            fw.remover_regras_tor('Tor:infra:')

            if iface_saida:
                nome_tcp_livre = 'Tor:infra:saida:livre'
                fw.adicionar_regra_automatica(
                    nome_tcp_livre,
                    {
                        'nome':      nome_tcp_livre,
                        'interface': iface_saida,
                        'direcao':   'out',
                        'protocolo': 'tcp',
                        'ip':        '',
                        'porta':     '',
                    },
                    FirewallUFW.CAT_TOR
                )

            if iface_saida:
                nome_dns = 'Tor:infra:saida:udp'
                fw.adicionar_regra_automatica(
                    nome_dns,
                    {
                        'nome':      nome_dns,
                        'interface': iface_saida,
                        'direcao':   'out',
                        'protocolo': 'udp',
                        'ip':        '',
                        'porta':     '53',
                    },
                    FirewallUFW.CAT_TOR
                )

            for info in TOR_PORTAS_SAIDA:
                nome = f'Tor:infra:saida:{info["porta"]}'
                fw.adicionar_regra_automatica(
                    nome,
                    {
                        'nome':      nome,
                        'interface': iface_saida,
                        'direcao':   'out',
                        'protocolo': info['proto'],
                        'ip':        '',
                        'porta':     info['porta'],
                    },
                    FirewallUFW.CAT_TOR
                )

            if iface_saida:
                nome_est = 'Tor:infra:entrada:est'
                fw.adicionar_regra_automatica(
                    nome_est,
                    {
                        'nome':      nome_est,
                        'interface': iface_saida,
                        'direcao':   'in',
                        'protocolo': 'tcp',
                        'ip':        '',
                        'porta':     '',
                    },
                    FirewallUFW.CAT_TOR
                )

            for info in TOR_PORTAS_LOCAL:
                for dir_ in ['in', 'out']:
                    nome = f'Tor:infra:lo:{dir_}:{info["porta"]}'
                    fw.adicionar_regra_automatica(
                        nome,
                        {
                            'nome':      nome,
                            'interface': 'lo',
                            'direcao':   dir_,
                            'protocolo': info['proto'],
                            'ip':        '127.0.0.0/8',
                            'porta':     info['porta'],
                        },
                        FirewallUFW.CAT_TOR
                    )

            logger.error(
                f"Regras Tor criadas: iface={iface_saida} "
                f"via_vpn={info_saida.get('via_vpn')}"
            )
            return True

        except Exception as e:
            logger.error(f"_garantir_regras_ufw_tor: {e}")
            return False

    def _remover_regras_ufw_tor_infra(self):
        with self._fw_lock:
            fw = self._firewall_ufw
        if not fw:
            return
        try:
            fw.remover_regras_tor('Tor:infra:')
        except Exception as e:
            logger.error(f"_remover_regras_ufw_tor_infra: {e}")

    # ══════════════════════════════════════════════════════
    # PERMISSÕES
    # ══════════════════════════════════════════════════════

    def _usuario_tor(self):
        for usuario in ['debian-tor', 'tor', '_tor']:
            r = executar_comando(
                f'id {usuario} 2>/dev/null', timeout=5
            )
            if r['sucesso'] and r['saida']:
                return usuario
        return 'debian-tor'

    def _corrigir_permissoes_todos(self):
        try:
            u = self._usuario_tor()
            os.makedirs(self.hs_dir, exist_ok=True)
            executar_comando(
                f'chown {u}:{u} {self.hs_dir}', timeout=5
            )
            executar_comando(
                f'chmod 700 {self.hs_dir}', timeout=5
            )
            for s in self.config.get('servicos', []):
                self._preparar_dir_hs(s.get('dir_id', ''), u)
        except Exception as e:
            logger.error(f"_corrigir_permissoes: {e}")

    def _preparar_dir_hs(self, dir_id, usuario_tor=None):
        if not dir_id:
            return
        try:
            u = usuario_tor or self._usuario_tor()
            p = os.path.join(
                self.hs_dir, f'hidden_service_{dir_id}'
            )
            os.makedirs(p, exist_ok=True)
            executar_comando(
                f'chown -R {u}:{u} {p}', timeout=5
            )
            executar_comando(f'chmod 700 {p}', timeout=5)
            r = executar_comando(
                f'stat -c "%U" {p}', timeout=5
            )
            if r['sucesso'] and r['saida'].strip() != u:
                logger.error(
                    f"AVISO: {p} dono={r['saida'].strip()} "
                    f"esperado={u}"
                )
        except Exception as e:
            logger.error(f"_preparar_dir_hs: {e}")

    def _liberar_leitura_hostname(self, dir_id):
        try:
            hp = os.path.join(
                self.hs_dir,
                f'hidden_service_{dir_id}',
                'hostname'
            )
            if os.path.exists(hp):
                executar_comando(
                    f'chmod o+r {hp} 2>/dev/null', timeout=5
                )
        except Exception as e:
            logger.error(f"_liberar_hostname: {e}")

    # ══════════════════════════════════════════════════════
    # POLLING
    # ══════════════════════════════════════════════════════

    def _poll_bootstrap_loop(self):
        for _ in range(120):
            time.sleep(5)
            pct = self._obter_bootstrap()
            if pct >= 100:
                for s in self.config.get('servicos', []):
                    if not s.get('pausado', False):
                        self._iniciar_polling_onion(s['dir_id'])
                return
        logger.error("Tor bootstrap não completou em 10min")

    def _iniciar_polling_onion(self, dir_id):
        if dir_id in self._polling:
            t = self._polling[dir_id]
            if t and t.is_alive():
                return
        t = threading.Thread(
            target=self._poll_onion_loop,
            args=(dir_id,),
            daemon=True,
            name=f'Tor-Onion-{dir_id}'
        )
        self._polling[dir_id] = t
        t.start()

    def _poll_onion_loop(self, dir_id):
        for _ in range(300):
            time.sleep(3)
            self._liberar_leitura_hostname(dir_id)
            if self._ler_onion(dir_id):
                return
        logger.error(f"Onion {dir_id} não gerado em 15min")

    def _aguardar_onion(self, dir_id, timeout=40):
        fim = time.time() + timeout
        while time.time() < fim:
            self._liberar_leitura_hostname(dir_id)
            o = self._ler_onion(dir_id)
            if o:
                return o
            time.sleep(2)
        return ''

    # ══════════════════════════════════════════════════════
    # SERVIÇOS
    # ══════════════════════════════════════════════════════

    def adicionar_servico(self, nome, porta_virtual,
                          porta_destino,
                          interface='localhost',
                          ip_destino_custom=''):
        try:
            porta_virtual = int(porta_virtual)
            porta_destino = int(porta_destino)
            nome          = nome.strip()

            if not nome:
                return {'sucesso': False,
                        'erro': 'Nome obrigatório'}

            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    return {'sucesso': False,
                            'erro': f'"{nome}" já existe'}

            # CORRIGIDO: prioriza IP customizado da UI
            if ip_destino_custom and ip_destino_custom.strip():
                ip_destino = ip_destino_custom.strip()
            else:
                ip_destino = self._ip_interface(interface)

            dir_id = self._gerar_id()

            self.config.setdefault('servicos', []).append({
                'nome':          nome,
                'dir_id':        dir_id,
                'porta_virtual': porta_virtual,
                'porta_destino': porta_destino,
                'interface':     interface,
                'ip_destino':    ip_destino,
                'pausado':       False,
                'criado_em':     datetime.now().isoformat()
            })
            self._salvar()

            self._preparar_dir_hs(dir_id)
            self._criar_regra_ufw_servico(
                nome, porta_destino, interface, ip_destino
            )

            onion = ''
            if self.config.get('ativo'):
                info = self._obter_info_saida()
                self._garantir_regras_ufw_tor(info)
                self._gerar_torrc()
                executar_comando(
                    'systemctl restart tor', timeout=30
                )
                self._iniciar_polling_onion(dir_id)
                onion = self._aguardar_onion(dir_id, timeout=40)

            return {
                'sucesso':  True,
                'mensagem': (
                    f'"{nome}" adicionado! '
                    f'Destino: {ip_destino}:{porta_destino}'
                ),
                'onion':   onion,
                'gerando': not bool(onion),
                'dir_id':  dir_id,
            }
        except ValueError:
            return {'sucesso': False, 'erro': 'Portas inválidas'}
        except Exception as e:
            logger.error(f"adicionar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def editar_servico(self, nome_orig, nome_novo,
                       porta_virtual, porta_destino,
                       interface='localhost',
                       ip_destino_custom=''):
        try:
            porta_virtual = int(porta_virtual)
            porta_destino = int(porta_destino)
            nome_novo     = nome_novo.strip()

            idx, srv = None, None
            for i, s in enumerate(
                self.config.get('servicos', [])
            ):
                if s.get('nome') == nome_orig:
                    idx, srv = i, s
                    break

            if srv is None:
                return {'sucesso': False,
                        'erro': f'"{nome_orig}" não encontrado'}

            # CORRIGIDO: prioriza IP customizado da UI
            if ip_destino_custom and ip_destino_custom.strip():
                ip_destino = ip_destino_custom.strip()
            else:
                ip_destino = self._ip_interface(interface)

            dir_id = srv.get('dir_id', '')

            self.config['servicos'][idx] = {
                'nome':          nome_novo,
                'dir_id':        dir_id,
                'porta_virtual': porta_virtual,
                'porta_destino': porta_destino,
                'interface':     interface,
                'ip_destino':    ip_destino,
                'pausado':       srv.get('pausado', False),
                'criado_em':     srv.get('criado_em', ''),
                'editado_em':    datetime.now().isoformat()
            }
            self._salvar()
            self._remover_regra_ufw_servico(nome_orig)
            self._criar_regra_ufw_servico(
                nome_novo, porta_destino, interface, ip_destino
            )

            if self.config.get('ativo'):
                info = self._obter_info_saida()
                self._garantir_regras_ufw_tor(info)
                self._gerar_torrc()
                executar_comando(
                    'systemctl restart tor', timeout=30
                )
            return {
                'sucesso':  True,
                'mensagem': (
                    f'"{nome_novo}" editado! '
                    f'Destino: {ip_destino}:{porta_destino}'
                )
            }
        except ValueError:
            return {'sucesso': False, 'erro': 'Portas inválidas'}
        except Exception as e:
            logger.error(f"editar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def pausar_servico(self, nome):
        try:
            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    s['pausado'] = not s.get('pausado', False)
                    self._salvar()
                    if self.config.get('ativo'):
                        info = self._obter_info_saida()
                        self._garantir_regras_ufw_tor(info)
                        self._gerar_torrc()
                        executar_comando(
                            'systemctl restart tor', timeout=30
                        )
                    est = ('pausado' if s['pausado']
                           else 'reativado')
                    return {'sucesso': True,
                            'mensagem': f'Serviço {est}'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"pausar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_servico(self, nome):
        try:
            servicos   = self.config.get('servicos', [])
            encontrado = None
            for i, s in enumerate(servicos):
                if s.get('nome') == nome:
                    encontrado = servicos.pop(i)
                    break
            if not encontrado:
                return {'sucesso': False,
                        'erro': 'Não encontrado'}

            self.config['servicos'] = servicos
            self._salvar()
            self._remover_regra_ufw_servico(nome)

            dir_id = encontrado.get('dir_id', '')
            if dir_id in self._polling:
                del self._polling[dir_id]

            hs_path = os.path.join(
                self.hs_dir, f'hidden_service_{dir_id}'
            )
            if os.path.exists(hs_path):
                shutil.rmtree(hs_path, ignore_errors=True)

            if self.config.get('ativo'):
                info = self._obter_info_saida()
                self._garantir_regras_ufw_tor(info)
                self._gerar_torrc()
                executar_comando(
                    'systemctl restart tor', timeout=30
                )
            return {'sucesso': True,
                    'mensagem': f'"{nome}" removido'}
        except Exception as e:
            logger.error(f"remover_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def renovar_onion(self, nome):
        try:
            for i, s in enumerate(
                self.config.get('servicos', [])
            ):
                if s.get('nome') == nome:
                    dir_id_ant = s.get('dir_id', '')
                    hs_path    = os.path.join(
                        self.hs_dir,
                        f'hidden_service_{dir_id_ant}'
                    )
                    if os.path.exists(hs_path):
                        shutil.rmtree(
                            hs_path, ignore_errors=True
                        )
                    if dir_id_ant in self._polling:
                        del self._polling[dir_id_ant]

                    novo_id = self._gerar_id()
                    self.config['servicos'][i]['dir_id'] = novo_id
                    self._salvar()
                    self._preparar_dir_hs(novo_id)

                    if self.config.get('ativo'):
                        info = self._obter_info_saida()
                        self._garantir_regras_ufw_tor(info)
                        self._gerar_torrc()
                        executar_comando(
                            'systemctl restart tor', timeout=30
                        )
                        self._iniciar_polling_onion(novo_id)
                        onion = self._aguardar_onion(
                            novo_id, timeout=40
                        )
                        return {
                            'sucesso':  True,
                            'mensagem': 'Endereço renovado!',
                            'onion':    onion,
                            'gerando':  not bool(onion),
                            'dir_id':   novo_id,
                        }
                    return {
                        'sucesso':  True,
                        'mensagem': 'Chaves removidas.',
                        'gerando':  True,
                        'dir_id':   novo_id,
                    }
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"renovar_onion: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def obter_onion(self, nome):
        try:
            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    dir_id = s.get('dir_id', '')
                    self._liberar_leitura_hostname(dir_id)
                    onion  = self._ler_onion(dir_id)
                    return {
                        'sucesso': True,
                        'onion':   onion,
                        'gerando': (
                            dir_id in self._polling and
                            self._polling[dir_id].is_alive()
                            and not onion
                        ),
                        'nome': nome
                    }
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"obter_onion: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # TORRC
    # ══════════════════════════════════════════════════════

    def _gerar_torrc(self):
        try:
            bkp = f'{self.torrc_path}.rrfs.bak'
            if (os.path.exists(self.torrc_path) and
                    not os.path.exists(bkp)):
                shutil.copy2(self.torrc_path, bkp)

            linhas_limpas = []
            em_bloco      = False

            if os.path.exists(self.torrc_path):
                with open(self.torrc_path, 'r') as f:
                    for linha in f:
                        if ('# === RRFS' in linha or
                                '# === FIM RRFS' in linha):
                            em_bloco = (
                                '# === FIM RRFS' not in linha
                            )
                            continue
                        if em_bloco:
                            continue
                        linhas_limpas.append(linha)

            novo_bloco = [
                '\n',
                '# === RRFS ===\n',
                f'# {datetime.now().isoformat()}\n',
                '\n',
            ]

            u = self._usuario_tor()

            for s in self.config.get('servicos', []):
                if s.get('pausado', False):
                    continue
                dir_id  = s.get('dir_id', '')
                hs_path = os.path.join(
                    self.hs_dir,
                    f'hidden_service_{dir_id}'
                )
                pv = s.get('porta_virtual', 80)
                pd = s.get('porta_destino', 80)
                ip = s.get('ip_destino', '127.0.0.1')

                os.makedirs(hs_path, exist_ok=True)
                executar_comando(
                    f'chown -R {u}:{u} {hs_path}',
                    timeout=5
                )
                executar_comando(
                    f'chmod 700 {hs_path}', timeout=5
                )

                novo_bloco += [
                    f'# {s.get("nome", "")}\n',
                    f'HiddenServiceDir {hs_path}\n',
                    f'HiddenServicePort {pv} {ip}:{pd}\n',
                    '\n',
                ]

            novo_bloco.append('# === FIM RRFS ===\n')

            with open(self.torrc_path, 'w') as f:
                f.writelines(linhas_limpas)
                f.writelines(novo_bloco)

            executar_comando(
                f'chmod 644 {self.torrc_path}', timeout=5
            )

            r_v = executar_comando(
                'tor --verify-config 2>&1', timeout=15
            )
            if 'error' in r_v.get('saida', '').lower():
                logger.error(
                    f"torrc inválido após geração: "
                    f"{r_v.get('saida', '')}"
                )

        except Exception as e:
            logger.error(f"gerar_torrc: {e}")

    # ══════════════════════════════════════════════════════
    # UFW SERVIÇO — CORRIGIDO v2.4
    # ══════════════════════════════════════════════════════

    def _criar_regra_ufw_servico(self, nome, porta,
                                  interface, ip):
        """
        CORRIGIDO v2.4:

        Caso 1 - localhost (127.x.x.x):
          → Regra de ENTRADA no loopback (lo)
          → O Tor lê da porta local sem sair para a rede

        Caso 2 - IP da LAN (192.168.x.x, 10.x, 172.16.x):
          → Regra de SAÍDA na interface física:
            Tor precisa ALCANÇAR o dispositivo remoto
          → Regra de ENTRADA na interface física:
            Respostas do dispositivo remoto voltam ao Tor
          Sem essas duas regras, o UFW com
          'default deny outgoing' bloqueia o tráfego LAN.
        """
        with self._fw_lock:
            fw = self._firewall_ufw
        if not fw:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW

            eh_local = (
                not interface or
                interface == 'localhost' or
                str(ip).startswith('127.')
            )

            if eh_local:
                # ── Caso 1: destino localhost ─────────────
                fw.adicionar_regra_automatica(
                    f'Tor:{nome}',
                    {
                        'nome':      f'Tor:{nome}',
                        'interface': 'lo',
                        'direcao':   'in',
                        'protocolo': 'tcp',
                        'ip':        '127.0.0.0/8',
                        'porta':     str(porta)
                    },
                    FirewallUFW.CAT_TOR
                )
            else:
                # ── Caso 2: destino LAN ───────────────────
                # Saída: Tor → dispositivo LAN (ip:porta)
                fw.adicionar_regra_automatica(
                    f'Tor:{nome}:out',
                    {
                        'nome':      f'Tor:{nome}:out',
                        'interface': interface,
                        'direcao':   'out',
                        'protocolo': 'tcp',
                        'ip':        ip,
                        'porta':     str(porta)
                    },
                    FirewallUFW.CAT_TOR
                )
                # Entrada: dispositivo LAN → Tor (respostas)
                fw.adicionar_regra_automatica(
                    f'Tor:{nome}:in',
                    {
                        'nome':      f'Tor:{nome}:in',
                        'interface': interface,
                        'direcao':   'in',
                        'protocolo': 'tcp',
                        'ip':        ip,
                        'porta':     str(porta)
                    },
                    FirewallUFW.CAT_TOR
                )

        except Exception as e:
            logger.error(f"_criar_regra_ufw_servico: {e}")

    def _remover_regra_ufw_servico(self, nome):
        with self._fw_lock:
            fw = self._firewall_ufw
        if not fw:
            return
        try:
            # Remove todas as variantes: Tor:nome,
            # Tor:nome:out, Tor:nome:in
            fw.remover_regras_tor(f'Tor:{nome}')
        except Exception as e:
            logger.error(f"_remover_regra_ufw_servico: {e}")

    # ══════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════

    def _ip_interface(self, interface):
        if not interface or interface == 'localhost':
            return '127.0.0.1'
        r = executar_comando(
            f"ip -4 addr show {interface} 2>/dev/null | "
            f"grep 'inet ' | awk '{{print $2}}' | "
            f"cut -d/ -f1 | head -1",
            timeout=10
        )
        v = r['saida'].strip() if r['sucesso'] else ''
        return v or '127.0.0.1'
