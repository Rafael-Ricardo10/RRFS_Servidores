#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tor_manager.py - RRFS Servidores v2.5
v2.5:
  - Removida a integração com conexao.py / VPN (interface de saída
    agora é sempre a rota default do sistema)
  - Nome e IP de destino validados (antes permitiam injetar linhas
    no torrc e comandos no shell)
  - Removida regra 'entrada:est' (abria TODA entrada TCP na WAN;
    respostas já passam pelo conntrack do UFW)
  - Removida regra ':in' de serviços LAN (mesmo motivo)
  - Remoção de regras de serviço agora é exata (serviço 'web' não
    apaga mais as regras do serviço 'web2')
  - Reinício do Tor via tor@default
"""

import os
import re
import json
import time
import shutil
import logging
import hashlib
import ipaddress
import threading
from datetime import datetime

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Tor')

RE_IFACE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
RE_NOME  = re.compile(r'^[\w .\-]{1,60}$', re.UNICODE)

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

    def set_firewall_ufw(self, fw):
        with self._fw_lock:
            self._firewall_ufw = fw
        if self.config.get('ativo') and fw:
            threading.Thread(
                target=self._garantir_regras_ufw_tor,
                daemon=True, name='Tor-FW-Init'
            ).start()

    # ══════════════════════════════════════════════════════
    # INTERFACE DE SAÍDA (rota default)
    # ══════════════════════════════════════════════════════

    def _obter_info_saida(self):
        """Chaves via_vpn/vpn_nome/tun_saida mantidas (sempre vazias)
        para não quebrar o front-end atual."""
        iface = self._rota_default_iface()
        return {
            'interface_saida': iface,
            'interface_wan':   iface,
            'via_vpn':         False,
            'vpn_nome':        '',
            'tun_saida':       '',
        }

    def _rota_default_iface(self):
        try:
            r = executar_comando(
                'ip route show default 2>/dev/null | '
                "awk '/default/ {print $5}' | head -1",
                timeout=10
            )
            if r['sucesso'] and r['saida'].strip():
                return r['saida'].strip()
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
            os.makedirs(os.path.dirname(self.config_path),
                        exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"tor salvar: {e}")

    def _gerar_id(self):
        raw = (f"{datetime.now().isoformat()}"
               f"{os.urandom(16).hex()}")
        return 'hs_' + hashlib.sha256(raw.encode()).hexdigest()[:12]

    def _reiniciar_tor(self):
        r = executar_comando('systemctl restart tor@default',
                             timeout=30)
        if not r['sucesso']:
            executar_comando('systemctl restart tor', timeout=30)

    def _validar_servico(self, nome, porta_virtual, porta_destino,
                         interface, ip_custom):
        nome = (nome or '').strip()
        if not RE_NOME.match(nome):
            return None, 'Nome inválido (letras, números, espaço, . -)'
        try:
            pv = int(porta_virtual)
            pd = int(porta_destino)
        except (TypeError, ValueError):
            return None, 'Portas inválidas'
        if not (1 <= pv <= 65535 and 1 <= pd <= 65535):
            return None, 'Portas: 1-65535'
        interface = (interface or 'localhost').strip()
        if interface != 'localhost' and not RE_IFACE.match(interface):
            return None, 'Interface inválida'
        ip_custom = (ip_custom or '').strip()
        if ip_custom:
            try:
                ipaddress.ip_address(ip_custom)
            except ValueError:
                return None, 'IP de destino inválido'
            ip = ip_custom
        else:
            ip = self._ip_interface(interface)
        return {'nome': nome, 'pv': pv, 'pd': pd,
                'interface': interface, 'ip': ip}, None

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
                        f'systemctl is-active {servico} 2>/dev/null'
                    )
                    s = r.get('saida', '')
                    if r['sucesso'] and 'active' in s and \
                            'inactive' not in s:
                        ativo = True
                        break
                if ativo:
                    bootstrap = self._obter_bootstrap()

            servicos   = self._servicos_com_onion()
            info_saida = self._obter_info_saida()
            problemas  = []
            if self._firewall_ufw:
                problemas = self._firewall_ufw.diagnosticar_regras_tor()

            return {
                'instalado':       instalado,
                'servico_ativo':   ativo,
                'ativo':           self.config.get('ativo', False),
                'bootstrap':       bootstrap,
                'servicos':        servicos,
                'total':           len(servicos),
                'fw_ok':           bool(self._firewall_ufw) and
                                   len(problemas) == 0,
                'fw_problemas':    problemas,
                'interface_saida': info_saida['interface_saida'],
                'interface_wan':   info_saida['interface_wan'],
                'via_vpn':         False,
                'vpn_nome':        '',
                'tun_saida':       '',
                'log_recente':     self._obter_log_tor(15),
            }
        except Exception as e:
            logger.error(f"tor obter_status: {e}")
            return {
                'instalado': False, 'servico_ativo': False,
                'ativo': False, 'bootstrap': 0, 'servicos': [],
                'total': 0, 'fw_ok': False, 'fw_problemas': [],
                'interface_saida': '', 'interface_wan': '',
                'via_vpn': False, 'vpn_nome': '', 'tun_saida': '',
                'log_recente': ''
            }

    def obter_status_resumido(self):
        try:
            r = executar_comando(
                'systemctl is-active tor@default 2>/dev/null'
            )
            ativo = r['sucesso'] and 'active' in r.get('saida', '')
            return {
                'servico_ativo': ativo,
                'ativo':         self.config.get('ativo', False),
                'servicos':      self._servicos_com_onion(),
                'total':         len(self.config.get('servicos', [])),
            }
        except Exception as e:
            logger.error(f"tor resumido: {e}")
            return {'servico_ativo': False, 'ativo': False,
                    'servicos': [], 'total': 0}

    def _instalado(self):
        r = executar_comando('which tor 2>/dev/null')
        return r['sucesso'] and bool(r.get('saida', '').strip())

    def _obter_bootstrap(self):
        try:
            for servico in ['tor@default', 'tor']:
                r = executar_comando(
                    f'journalctl -u {servico} '
                    f'--since "30 minutes ago" --no-pager -q '
                    f'2>/dev/null | grep -i "bootstrapped" | tail -5',
                    timeout=15
                )
                if r['sucesso'] and r['saida']:
                    for l in reversed(r['saida'].splitlines()):
                        m = re.search(r'Bootstrapped\s+(\d+)%', l,
                                      re.I)
                        if m:
                            return int(m.group(1))
            for lp in ['/var/log/tor/log', '/var/log/tor/notices.log']:
                if not os.path.exists(lp):
                    continue
                r2 = executar_comando(
                    f'grep -i "bootstrapped" {lp} 2>/dev/null | '
                    f'tail -5', timeout=10
                )
                if r2['sucesso'] and r2['saida']:
                    for l in reversed(r2['saida'].splitlines()):
                        m = re.search(r'Bootstrapped\s+(\d+)%', l,
                                      re.I)
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
                    f'--since "10 minutes ago" --no-pager -q '
                    f'2>/dev/null | tail -{int(linhas)}',
                    timeout=10
                )
                if r['sucesso'] and r['saida']:
                    return r['saida']
            for lp in ['/var/log/tor/log', '/var/log/tor/notices.log']:
                if os.path.exists(lp):
                    r2 = executar_comando(
                        f'tail -{int(linhas)} {lp} 2>/dev/null',
                        timeout=5
                    )
                    if r2['sucesso']:
                        return r2['saida']
        except Exception as e:
            logger.error(f"_obter_log_tor: {e}")
        return ''

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
        path = os.path.join(self.hs_dir,
                            f'hidden_service_{dir_id}', 'hostname')
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
                r = executar_comando('apt-get install -y tor',
                                     timeout=300)
                if not r['sucesso']:
                    return {'sucesso': False,
                            'erro': 'Falha ao instalar Tor'}

            info        = self._obter_info_saida()
            iface_saida = info['interface_saida']

            r_fw = self._garantir_regras_ufw_tor(info)
            self._corrigir_permissoes_todos()
            self._gerar_torrc()

            r_v = executar_comando('tor --verify-config 2>&1',
                                   timeout=15)
            saida_v = r_v.get('saida', '')
            if ('err' in saida_v.lower() and
                    'Configuration was valid' not in saida_v):
                return {'sucesso': False,
                        'erro': f'Config inválida: {saida_v[-300:]}'}

            executar_comando('systemctl enable tor@default',
                             timeout=10)
            self._reiniciar_tor()

            time.sleep(2)
            r_st = executar_comando(
                'systemctl is-active tor@default 2>/dev/null',
                timeout=5
            )
            if not (r_st['sucesso'] and
                    'active' in r_st.get('saida', '')):
                log = self._obter_log_tor(30)
                return {'sucesso': False,
                        'erro': f'Tor não iniciou: {log[-300:]}'}

            self.config['ativo'] = True
            self._salvar()

            threading.Thread(target=self._poll_bootstrap_loop,
                             daemon=True, name='Tor-Bootstrap').start()

            return {
                'sucesso':         True,
                'mensagem':        (f'Tor ativado! Saída via '
                                    f'{iface_saida or "rota padrão"}. '
                                    f'Aguardando bootstrap...'),
                'fw_configurado':  r_fw,
                'interface_saida': iface_saida,
                'via_vpn':         False,
                'vpn_nome':        '',
            }
        except Exception as e:
            logger.error(f"tor ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def desativar(self):
        try:
            executar_comando('systemctl stop tor@default 2>/dev/null',
                             timeout=30)
            executar_comando('systemctl stop tor 2>/dev/null',
                             timeout=10)
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
            if not self._garantir_regras_ufw_tor(info):
                return {'sucesso': False,
                        'erro': 'Firewall não disponível'}
            return {
                'sucesso':         True,
                'mensagem':        'Regras recriadas com sucesso!',
                'problemas':       self._firewall_ufw
                                   .diagnosticar_regras_tor(),
                'interface_saida': info['interface_saida'],
                'via_vpn':         False,
                'vpn_nome':        '',
            }
        except Exception as e:
            logger.error(f"reparar_firewall: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def obter_diagnostico(self):
        try:
            info = self._obter_info_saida()
            r_v  = executar_comando('tor --verify-config 2>&1',
                                    timeout=15)
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
                    f'timeout 5 nc -z -w 3 check.torproject.org '
                    f'{porta} 2>/dev/null && echo OK || echo FAIL',
                    timeout=10
                )
                conectividade[porta] = 'OK' in r_nc.get('saida', '')

            return {
                'sucesso':         True,
                'bootstrap':       self._obter_bootstrap(),
                'log':             self._obter_log_tor(30),
                'interface_saida': info['interface_saida'],
                'interface_wan':   info['interface_wan'],
                'via_vpn':         False,
                'vpn_nome':        '',
                'tun_saida':       '',
                'torrc_ok':        'Configuration was valid' in
                                   r_v.get('saida', ''),
                'torrc_conteudo':  torrc_txt,
                'conectividade':   conectividade,
                'fw_problemas':    self._firewall_ufw
                                   .diagnosticar_regras_tor()
                                   if self._firewall_ufw else [],
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
        iface = info_saida.get('interface_saida', '')

        try:
            from modulos.firewall_ufw import FirewallUFW
            cat = FirewallUFW.CAT_TOR
            fw.remover_regras_prefixo(cat, 'Tor:infra:')

            def regra(nome, interface, direcao, proto, ip, porta):
                fw.adicionar_regra_automatica(nome, {
                    'nome': nome, 'interface': interface,
                    'direcao': direcao, 'protocolo': proto,
                    'ip': ip, 'porta': porta
                }, cat)

            # saída TCP irrestrita na interface de saída
            # (relays Tor usam portas variadas)
            if iface:
                regra('Tor:infra:saida:livre', iface,
                      'out', 'tcp', '', '')

            for p in TOR_PORTAS_SAIDA:
                regra(f'Tor:infra:saida:{p["porta"]}', iface,
                      'out', p['proto'], '', p['porta'])

            for p in TOR_PORTAS_LOCAL:
                for d in ('in', 'out'):
                    regra(f'Tor:infra:lo:{d}:{p["porta"]}', 'lo',
                          d, p['proto'], '127.0.0.0/8', p['porta'])

            # serviços existentes (caso a interface tenha mudado)
            for s in self.config.get('servicos', []):
                self._remover_regra_ufw_servico(s.get('nome', ''))
                self._criar_regra_ufw_servico(
                    s.get('nome', ''), s.get('porta_destino', 80),
                    s.get('interface', 'localhost'),
                    s.get('ip_destino', '127.0.0.1')
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
            r = executar_comando(f'id {usuario} 2>/dev/null',
                                 timeout=5)
            if r['sucesso'] and r['saida']:
                return usuario
        return 'debian-tor'

    def _corrigir_permissoes_todos(self):
        try:
            u = self._usuario_tor()
            os.makedirs(self.hs_dir, exist_ok=True)
            executar_comando(f'chown {u}:{u} {self.hs_dir}', timeout=5)
            executar_comando(f'chmod 700 {self.hs_dir}', timeout=5)
            for s in self.config.get('servicos', []):
                self._preparar_dir_hs(s.get('dir_id', ''), u)
        except Exception as e:
            logger.error(f"_corrigir_permissoes: {e}")

    def _preparar_dir_hs(self, dir_id, usuario_tor=None):
        if not dir_id:
            return
        try:
            u = usuario_tor or self._usuario_tor()
            p = os.path.join(self.hs_dir, f'hidden_service_{dir_id}')
            os.makedirs(p, exist_ok=True)
            executar_comando(f'chown -R {u}:{u} {p}', timeout=5)
            executar_comando(f'chmod 700 {p}', timeout=5)
        except Exception as e:
            logger.error(f"_preparar_dir_hs: {e}")

    def _liberar_leitura_hostname(self, dir_id):
        try:
            hp = os.path.join(self.hs_dir,
                              f'hidden_service_{dir_id}', 'hostname')
            if os.path.exists(hp):
                executar_comando(f'chmod o+r {hp} 2>/dev/null',
                                 timeout=5)
        except Exception as e:
            logger.error(f"_liberar_hostname: {e}")

    # ══════════════════════════════════════════════════════
    # POLLING
    # ══════════════════════════════════════════════════════

    def _poll_bootstrap_loop(self):
        for _ in range(120):
            time.sleep(5)
            if self._obter_bootstrap() >= 100:
                for s in self.config.get('servicos', []):
                    if not s.get('pausado', False):
                        self._iniciar_polling_onion(s['dir_id'])
                return
        logger.error("Tor bootstrap não completou em 10min")

    def _iniciar_polling_onion(self, dir_id):
        t = self._polling.get(dir_id)
        if t and t.is_alive():
            return
        t = threading.Thread(target=self._poll_onion_loop,
                             args=(dir_id,), daemon=True,
                             name=f'Tor-Onion-{dir_id}')
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

    def _aplicar_se_ativo(self):
        if self.config.get('ativo'):
            info = self._obter_info_saida()
            self._garantir_regras_ufw_tor(info)
            self._gerar_torrc()
            self._reiniciar_tor()

    # ══════════════════════════════════════════════════════
    # SERVIÇOS
    # ══════════════════════════════════════════════════════

    def adicionar_servico(self, nome, porta_virtual, porta_destino,
                          interface='localhost', ip_destino_custom=''):
        try:
            v, err = self._validar_servico(
                nome, porta_virtual, porta_destino,
                interface, ip_destino_custom
            )
            if err:
                return {'sucesso': False, 'erro': err}
            nome = v['nome']
            if any(s.get('nome') == nome
                   for s in self.config.get('servicos', [])):
                return {'sucesso': False,
                        'erro': f'"{nome}" já existe'}

            dir_id = self._gerar_id()
            self.config.setdefault('servicos', []).append({
                'nome':          nome,
                'dir_id':        dir_id,
                'porta_virtual': v['pv'],
                'porta_destino': v['pd'],
                'interface':     v['interface'],
                'ip_destino':    v['ip'],
                'pausado':       False,
                'criado_em':     datetime.now().isoformat()
            })
            self._salvar()

            self._preparar_dir_hs(dir_id)
            self._criar_regra_ufw_servico(
                nome, v['pd'], v['interface'], v['ip']
            )

            onion = ''
            if self.config.get('ativo'):
                self._aplicar_se_ativo()
                self._iniciar_polling_onion(dir_id)
                onion = self._aguardar_onion(dir_id, timeout=40)

            return {
                'sucesso':  True,
                'mensagem': (f'"{nome}" adicionado! '
                             f'Destino: {v["ip"]}:{v["pd"]}'),
                'onion':    onion,
                'gerando':  not bool(onion),
                'dir_id':   dir_id,
            }
        except Exception as e:
            logger.error(f"adicionar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def editar_servico(self, nome_orig, nome_novo, porta_virtual,
                       porta_destino, interface='localhost',
                       ip_destino_custom=''):
        try:
            v, err = self._validar_servico(
                nome_novo, porta_virtual, porta_destino,
                interface, ip_destino_custom
            )
            if err:
                return {'sucesso': False, 'erro': err}

            idx, srv = None, None
            for i, s in enumerate(self.config.get('servicos', [])):
                if s.get('nome') == nome_orig:
                    idx, srv = i, s
                    break
            if srv is None:
                return {'sucesso': False,
                        'erro': f'"{nome_orig}" não encontrado'}
            if v['nome'] != nome_orig and any(
                    s.get('nome') == v['nome']
                    for s in self.config['servicos']):
                return {'sucesso': False,
                        'erro': f'"{v["nome"]}" já existe'}

            self.config['servicos'][idx] = {
                'nome':          v['nome'],
                'dir_id':        srv.get('dir_id', ''),
                'porta_virtual': v['pv'],
                'porta_destino': v['pd'],
                'interface':     v['interface'],
                'ip_destino':    v['ip'],
                'pausado':       srv.get('pausado', False),
                'criado_em':     srv.get('criado_em', ''),
                'editado_em':    datetime.now().isoformat()
            }
            self._salvar()
            self._remover_regra_ufw_servico(nome_orig)
            self._criar_regra_ufw_servico(
                v['nome'], v['pd'], v['interface'], v['ip']
            )
            self._aplicar_se_ativo()
            return {'sucesso': True,
                    'mensagem': (f'"{v["nome"]}" editado! '
                                 f'Destino: {v["ip"]}:{v["pd"]}')}
        except Exception as e:
            logger.error(f"editar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def pausar_servico(self, nome):
        try:
            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    s['pausado'] = not s.get('pausado', False)
                    self._salvar()
                    self._aplicar_se_ativo()
                    est = 'pausado' if s['pausado'] else 'reativado'
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
                return {'sucesso': False, 'erro': 'Não encontrado'}

            self.config['servicos'] = servicos
            self._salvar()
            self._remover_regra_ufw_servico(nome)

            dir_id = encontrado.get('dir_id', '')
            self._polling.pop(dir_id, None)
            hs_path = os.path.join(self.hs_dir,
                                   f'hidden_service_{dir_id}')
            if dir_id and os.path.exists(hs_path):
                shutil.rmtree(hs_path, ignore_errors=True)

            self._aplicar_se_ativo()
            return {'sucesso': True, 'mensagem': f'"{nome}" removido'}
        except Exception as e:
            logger.error(f"remover_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def renovar_onion(self, nome):
        try:
            for i, s in enumerate(self.config.get('servicos', [])):
                if s.get('nome') != nome:
                    continue
                dir_ant = s.get('dir_id', '')
                hs_path = os.path.join(self.hs_dir,
                                       f'hidden_service_{dir_ant}')
                if dir_ant and os.path.exists(hs_path):
                    shutil.rmtree(hs_path, ignore_errors=True)
                self._polling.pop(dir_ant, None)

                novo_id = self._gerar_id()
                self.config['servicos'][i]['dir_id'] = novo_id
                self._salvar()
                self._preparar_dir_hs(novo_id)

                if self.config.get('ativo'):
                    self._aplicar_se_ativo()
                    self._iniciar_polling_onion(novo_id)
                    onion = self._aguardar_onion(novo_id, timeout=40)
                    return {'sucesso': True,
                            'mensagem': 'Endereço renovado!',
                            'onion': onion, 'gerando': not bool(onion),
                            'dir_id': novo_id}
                return {'sucesso': True,
                        'mensagem': 'Chaves removidas.',
                        'gerando': True, 'dir_id': novo_id}
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
                    onion = self._ler_onion(dir_id)
                    return {
                        'sucesso': True, 'onion': onion, 'nome': nome,
                        'gerando': (dir_id in self._polling and
                                    self._polling[dir_id].is_alive()
                                    and not onion),
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
                            em_bloco = '# === FIM RRFS' not in linha
                            continue
                        if em_bloco:
                            continue
                        linhas_limpas.append(linha)

            novo_bloco = ['\n', '# === RRFS ===\n',
                          f'# {datetime.now().isoformat()}\n', '\n']
            u = self._usuario_tor()

            for s in self.config.get('servicos', []):
                if s.get('pausado', False):
                    continue
                dir_id  = s.get('dir_id', '')
                hs_path = os.path.join(self.hs_dir,
                                       f'hidden_service_{dir_id}')
                pv = int(s.get('porta_virtual', 80))
                pd = int(s.get('porta_destino', 80))
                ip = str(s.get('ip_destino', '127.0.0.1'))
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    logger.error(f"torrc: IP inválido ignorado: {ip}")
                    continue
                nome_seguro = re.sub(r'[^\w .\-]', '_',
                                     str(s.get('nome', '')))

                os.makedirs(hs_path, exist_ok=True)
                executar_comando(f'chown -R {u}:{u} {hs_path}',
                                 timeout=5)
                executar_comando(f'chmod 700 {hs_path}', timeout=5)

                novo_bloco += [
                    f'# {nome_seguro}\n',
                    f'HiddenServiceDir {hs_path}\n',
                    f'HiddenServicePort {pv} {ip}:{pd}\n',
                    '\n',
                ]
            novo_bloco.append('# === FIM RRFS ===\n')

            with open(self.torrc_path, 'w') as f:
                f.writelines(linhas_limpas)
                f.writelines(novo_bloco)
            executar_comando(f'chmod 644 {self.torrc_path}', timeout=5)

            r_v = executar_comando('tor --verify-config 2>&1',
                                   timeout=15)
            if 'error' in r_v.get('saida', '').lower():
                logger.error(f"torrc inválido após geração: "
                             f"{r_v.get('saida', '')}")
        except Exception as e:
            logger.error(f"gerar_torrc: {e}")

    # ══════════════════════════════════════════════════════
    # UFW SERVIÇO
    # ══════════════════════════════════════════════════════

    def _criar_regra_ufw_servico(self, nome, porta, interface, ip):
        """
        localhost: regra de entrada no loopback.
        LAN: regra de SAÍDA na interface para ip:porta (as respostas
        voltam pelo conntrack do UFW, sem regra de entrada).
        """
        with self._fw_lock:
            fw = self._firewall_ufw
        if not fw:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            eh_local = (not interface or interface == 'localhost' or
                        str(ip).startswith('127.'))
            if eh_local:
                fw.adicionar_regra_automatica(f'Tor:{nome}', {
                    'nome': f'Tor:{nome}', 'interface': 'lo',
                    'direcao': 'in', 'protocolo': 'tcp',
                    'ip': '127.0.0.0/8', 'porta': str(porta)
                }, FirewallUFW.CAT_TOR)
            else:
                fw.adicionar_regra_automatica(f'Tor:{nome}:out', {
                    'nome': f'Tor:{nome}:out', 'interface': interface,
                    'direcao': 'out', 'protocolo': 'tcp',
                    'ip': ip, 'porta': str(porta)
                }, FirewallUFW.CAT_TOR)
        except Exception as e:
            logger.error(f"_criar_regra_ufw_servico: {e}")

    def _remover_regra_ufw_servico(self, nome):
        with self._fw_lock:
            fw = self._firewall_ufw
        if not fw:
            return
        try:
            fw.remover_regras_tor(f'Tor:{nome}', exato=True)
        except Exception as e:
            logger.error(f"_remover_regra_ufw_servico: {e}")

    # ══════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════

    def _ip_interface(self, interface):
        if (not interface or interface == 'localhost' or
                not RE_IFACE.match(interface)):
            return '127.0.0.1'
        r = executar_comando(
            f"ip -4 addr show {interface} 2>/dev/null | "
            f"grep 'inet ' | awk '{{print $2}}' | "
            f"cut -d/ -f1 | head -1", timeout=10
        )
        v = r['saida'].strip() if r['sucesso'] else ''
        return v or '127.0.0.1'
