#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
firewall_ufw.py - RRFS Servidores v2.3
CORRIGIDO v2.3:
  - obter_interfaces_disponiveis: retorna TODAS as interfaces
    incluindo bridge, docker, veth, tun, vlan, loopback
  - _detectar_tipo_interface: detecta tipo por nome e sysfs
  - _label_interface: label legível para cada tipo
  - _obter_ip_interface: obtém IP de qualquer interface
  - Ordenação: físicas primeiro, virtuais depois
  - Opção 'any' (qualquer interface) sempre disponível
"""

import os
import re
import json
import time
import uuid
import logging
import threading
import subprocess
from datetime import datetime

logger = logging.getLogger('RRFS.UFW')

PORTA_SISTEMA = 2000


def _encontrar_ufw():
    import shutil
    for c in ['/usr/sbin/ufw', '/sbin/ufw',
              '/usr/bin/ufw', '/bin/ufw']:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return shutil.which('ufw')


def _exec_ufw(args, timeout=30):
    ufw = _encontrar_ufw()
    if not ufw:
        return {'sucesso': False, 'saida': '',
                'erro': 'UFW não encontrado', 'codigo': -1}
    try:
        r = subprocess.run(
            f'{ufw} {args}',
            shell=True, capture_output=True,
            text=True, timeout=timeout,
            env={
                **os.environ,
                'PATH': (
                    '/usr/local/sbin:/usr/local/bin:'
                    '/usr/sbin:/usr/bin:/sbin:/bin'
                ),
                'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8'
            }
        )
        saida = r.stdout.strip()
        erro  = r.stderr.strip()
        ok    = (
            r.returncode == 0 or
            'Rule added' in saida or
            'Rules updated' in saida or
            'Skipping' in saida or
            'already exists' in saida or
            'Rule added' in erro or
            'Rules updated' in erro
        )
        return {
            'sucesso': ok,
            'saida':   saida,
            'erro':    erro,
            'codigo':  r.returncode
        }
    except subprocess.TimeoutExpired:
        logger.error(f"UFW timeout: {args}")
        return {'sucesso': False, 'saida': '',
                'erro': 'Timeout', 'codigo': -1}
    except Exception as e:
        logger.error(f"_exec_ufw '{args}': {e}")
        return {'sucesso': False, 'saida': '',
                'erro': str(e), 'codigo': -1}


class FirewallUFW:

    CAT_USUARIO  = 'usuario'
    CAT_SISTEMA  = 'sistema'
    CAT_TOR      = 'tor'
    CAT_VPN      = 'vpn'
    CAT_VPN_AUTO = 'vpn_auto'

    def __init__(self, base_dir):
        self.base_dir  = base_dir
        self._path     = os.path.join(
            base_dir, 'dados', 'regras_ufw.json'
        )
        self._cfg_path = os.path.join(
            base_dir, 'dados', 'config_ufw.json'
        )
        self.regras    = []
        self._config   = {}
        self._pendente = None
        self._timer    = None
        self._lock     = threading.Lock()
        self._carregar()
        self._carregar_config()

    # ══════════════════════════════════════════════════════
    # PERSISTÊNCIA
    # ══════════════════════════════════════════════════════

    def _carregar(self):
        try:
            if os.path.exists(self._path):
                with open(self._path, 'r',
                          encoding='utf-8') as f:
                    self.regras = json.load(f)
        except Exception as e:
            logger.error(f"carregar regras: {e}")
            self.regras = []

    def _salvar(self):
        try:
            os.makedirs(
                os.path.dirname(self._path), exist_ok=True
            )
            with open(self._path, 'w', encoding='utf-8') as f:
                json.dump(self.regras, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"salvar regras: {e}")

    def _carregar_config(self):
        try:
            if os.path.exists(self._cfg_path):
                with open(self._cfg_path, 'r',
                          encoding='utf-8') as f:
                    self._config = json.load(f)
        except Exception as e:
            logger.error(f"carregar config ufw: {e}")
            self._config = {}

    def _salvar_config(self):
        try:
            os.makedirs(
                os.path.dirname(self._cfg_path),
                exist_ok=True
            )
            with open(self._cfg_path, 'w',
                      encoding='utf-8') as f:
                json.dump(self._config, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"salvar config ufw: {e}")

    # ══════════════════════════════════════════════════════
    # INICIALIZAÇÃO
    # ══════════════════════════════════════════════════════

    def inicializar(self):
        try:
            _exec_ufw('default deny incoming')
            _exec_ufw('default deny outgoing')
            _exec_ufw('--force enable')

            for r in self.regras:
                if (not r.get('pausada') and
                        r.get('categoria') != self.CAT_SISTEMA):
                    args = r.get('ufw_args', '')
                    if args:
                        res = _exec_ufw(args)
                        if not res['sucesso']:
                            logger.error(
                                f"Reaplicar falhou: {args} "
                                f"→ {res['erro']}"
                            )
        except Exception as e:
            logger.error(f"inicializar ufw: {e}")

    def garantir_regra_sistema(self):
        try:
            with self._lock:
                self.regras = [
                    r for r in self.regras
                    if r.get('categoria') != self.CAT_SISTEMA
                ]
                interface = self._config.get(
                    'interface_sistema', ''
                )
                args = self._montar_args_porta_sistema(interface)
                res  = _exec_ufw(args)

                if not res['sucesso']:
                    logger.error(
                        f"garantir_regra_sistema falhou: "
                        f"{res['erro']}"
                    )

                regra = {
                    'id':          'sistema_porta_2000',
                    'nome':        'RRFS Sistema (porta 2000)',
                    'categoria':   self.CAT_SISTEMA,
                    'interface':   interface,
                    'direcao':     'in',
                    'protocolo':   'tcp',
                    'ip':          '',
                    'porta':       str(PORTA_SISTEMA),
                    'ufw_args':    args,
                    'delete_args': f'delete {args}',
                    'pausada':     False,
                    'editavel':    False,
                    'timestamp':   datetime.now().isoformat()
                }
                self.regras.insert(0, regra)
                self._salvar()
        except Exception as e:
            logger.error(f"garantir_regra_sistema: {e}")

    def _montar_args_porta_sistema(self, interface=''):
        if interface:
            return (
                f'allow in on {interface} '
                f'to any port {PORTA_SISTEMA} proto tcp'
            )
        return f'allow in to any port {PORTA_SISTEMA} proto tcp'

    # ══════════════════════════════════════════════════════
    # STATUS
    # ══════════════════════════════════════════════════════

    def obter_status(self):
        try:
            r   = _exec_ufw('status verbose')
            txt = r.get('saida', '')
            return {
                'ativo':            'active' in txt.lower(),
                'politica_entrada': self._pol(txt, 'incoming'),
                'politica_saida':   self._pol(txt, 'outgoing'),
                'texto':            txt
            }
        except Exception as e:
            logger.error(f"obter_status ufw: {e}")
            return {
                'ativo': False,
                'politica_entrada': 'unknown',
                'politica_saida':   'unknown',
                'texto': ''
            }

    def _pol(self, txt, termo):
        t = txt.lower()
        if f'deny ({termo})'  in t: return 'deny'
        if f'allow ({termo})' in t: return 'allow'
        return 'unknown'

    def listar_regras_salvas(self):
        return self.regras

    # ══════════════════════════════════════════════════════
    # INTERFACES — CORRIGIDO v2.3
    # ══════════════════════════════════════════════════════

    def obter_interfaces_disponiveis(self):
        """
        CORRIGIDO v2.3:
        Retorna TODAS as interfaces do sistema para
        seleção no firewall, incluindo:
        - Opção 'any' (sem interface específica)
        - Loopback (lo)
        - Físicas (ethernet, wifi)
        - Túneis VPN (tun, tap, wg)
        - Bridge (br-, docker, virbr)
        - Virtuais (veth, dummy, vlan)
        Ordenadas: físicas primeiro, virtuais depois.
        """
        try:
            interfaces = []

            # ── Opção especial: qualquer interface ────────
            interfaces.append({
                'nome':  '',
                'label': 'Qualquer interface (any)',
                'tipo':  'any',
                'ativa': True,
                'ip':    '',
                'mac':   '',
            })

            # ── Loopback ──────────────────────────────────
            interfaces.append({
                'nome':  'lo',
                'label': 'lo — Loopback (127.0.0.1)',
                'tipo':  'loopback',
                'ativa': True,
                'ip':    '127.0.0.1',
                'mac':   '',
            })

            # ── Todas as interfaces do kernel ─────────────
            r = subprocess.run(
                'ip -o link show',
                shell=True,
                capture_output=True,
                text=True
            )
            if r.returncode != 0:
                return interfaces

            for linha in r.stdout.splitlines():
                # Formato: "2: eth0: <FLAGS> ..."
                # ou "3: eth0@if4: <FLAGS> ..."
                m = re.match(r'\d+:\s+(\S+?)(@\S+)?:', linha)
                if not m:
                    continue

                nome = m.group(1).strip()

                # Pular loopback (já adicionado)
                if nome == 'lo':
                    continue

                tipo  = self._detectar_tipo_interface(nome, linha)
                label = self._label_interface(nome, tipo)
                ativa = ('UP' in linha and 'LOWER_UP' in linha)
                ip    = self._obter_ip_interface(nome)
                mac   = self._obter_mac_interface(nome)

                interfaces.append({
                    'nome':  nome,
                    'label': label,
                    'tipo':  tipo,
                    'ativa': ativa,
                    'ip':    ip,
                    'mac':   mac,
                })

            # ── Ordenar por tipo e nome ───────────────────
            ordem_tipo = {
                'any':        0,
                'loopback':   1,
                'ethernet':   2,
                'wifi':       3,
                'vpn_tunnel': 4,
                'wireguard':  5,
                'bridge':     6,
                'docker':     7,
                'veth':       8,
                'vlan':       9,
                'virtual':    10,
                'outro':      11,
            }
            interfaces.sort(
                key=lambda x: (
                    ordem_tipo.get(x['tipo'], 99),
                    x['nome']
                )
            )

            return interfaces

        except Exception as e:
            logger.error(f"obter_interfaces_disponiveis: {e}")
            return []

    def _detectar_tipo_interface(self, nome, linha_ip=''):
        """
        Detecta o tipo da interface pelo nome,
        flags e estrutura do sysfs.
        """
        # ── Túneis VPN ────────────────────────────────────
        if nome.startswith('tun'):
            return 'vpn_tunnel'
        if nome.startswith('tap'):
            return 'vpn_tunnel'

        # ── WireGuard ─────────────────────────────────────
        if nome.startswith('wg'):
            return 'wireguard'

        # ── Docker ────────────────────────────────────────
        if nome == 'docker0' or nome.startswith('docker'):
            return 'docker'

        # ── veth (containers/namespaces) ──────────────────
        if nome.startswith('veth'):
            return 'veth'

        # ── Bridge ────────────────────────────────────────
        if nome.startswith('virbr'):
            return 'bridge'
        if nome.startswith('br-'):
            return 'bridge'
        if nome.startswith('br'):
            # Confirmar via sysfs
            if os.path.exists(f'/sys/class/net/{nome}/bridge'):
                return 'bridge'

        # ── VLAN (ex: eth0.100, enp3s0.10) ───────────────
        if re.match(r'.+\.\d+$', nome):
            return 'vlan'

        # ── Dummy / virtual ───────────────────────────────
        if nome.startswith('dummy'):
            return 'virtual'
        if nome.startswith('sit'):
            return 'virtual'
        if nome.startswith('ip6tnl'):
            return 'virtual'

        # ── WiFi — via sysfs ──────────────────────────────
        sysfs = f'/sys/class/net/{nome}'
        try:
            if (os.path.exists(f'{sysfs}/wireless') or
                    os.path.exists(f'{sysfs}/phy80211')):
                return 'wifi'
        except Exception:
            pass

        # ── WiFi — por nome ───────────────────────────────
        for pfx in ['wlan', 'wlp', 'wlx', 'wls', 'ath',
                    'ra', 'rausb']:
            if nome.startswith(pfx):
                return 'wifi'

        # ── Ethernet física — via sysfs ───────────────────
        try:
            if os.path.exists(f'{sysfs}/device'):
                return 'ethernet'
        except Exception:
            pass

        # ── Ethernet — por nome ───────────────────────────
        for pfx in ['eth', 'enp', 'ens', 'eno', 'enx',
                    'lan', 'wan', 'em']:
            if nome.startswith(pfx):
                return 'ethernet'

        return 'outro'

    def _label_interface(self, nome, tipo):
        """Gera label legível para exibição na UI"""
        ip = self._obter_ip_interface(nome)
        ip_str = f' ({ip})' if ip else ''

        labels = {
            'ethernet':   f'{nome} — Ethernet{ip_str}',
            'wifi':       f'{nome} — WiFi{ip_str}',
            'vpn_tunnel': f'{nome} — Túnel VPN{ip_str}',
            'wireguard':  f'{nome} — WireGuard{ip_str}',
            'bridge':     f'{nome} — Bridge{ip_str}',
            'docker':     f'{nome} — Docker{ip_str}',
            'veth':       f'{nome} — Container{ip_str}',
            'vlan':       f'{nome} — VLAN{ip_str}',
            'virtual':    f'{nome} — Virtual{ip_str}',
            'loopback':   f'{nome} — Loopback (127.0.0.1)',
            'outro':      f'{nome}{ip_str}',
        }
        return labels.get(tipo, f'{nome}{ip_str}')

    def _obter_ip_interface(self, nome):
        """Obtém IP IPv4 da interface"""
        try:
            r = subprocess.run(
                f'ip -4 addr show {nome} 2>/dev/null',
                shell=True,
                capture_output=True,
                text=True
            )
            if r.returncode == 0:
                m = re.search(
                    r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                    r.stdout
                )
                if m:
                    return m.group(1)
        except Exception:
            pass
        return ''

    def _obter_mac_interface(self, nome):
        """Obtém endereço MAC da interface"""
        try:
            mac_path = f'/sys/class/net/{nome}/address'
            if os.path.exists(mac_path):
                with open(mac_path) as f:
                    mac = f.read().strip()
                # MAC zerado = interface virtual sem MAC
                if mac and mac != '00:00:00:00:00:00':
                    return mac
        except Exception:
            pass
        return ''

    # ══════════════════════════════════════════════════════
    # VALIDAÇÕES
    # ══════════════════════════════════════════════════════

    def _validar_porta(self, porta):
        porta = str(porta).strip()
        if ':' in porta:
            p = porta.split(':')
            if len(p) != 2:
                return False, 'Range inválido. Ex: 8000:9000'
            for x in p:
                if (not x.strip().isdigit() or
                        not (1 <= int(x.strip()) <= 65535)):
                    return False, f'Porta inválida: {x}'
            if int(p[0]) >= int(p[1]):
                return False, 'Porta inicial >= final'
        else:
            if not porta.isdigit():
                return False, 'Porta deve ser número'
            if not (1 <= int(porta) <= 65535):
                return False, 'Porta: 1-65535'
        return True, ''

    def _validar_ip(self, ip):
        ip = ip.strip()
        if not re.match(
            r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$', ip
        ):
            return False, f'IP inválido: {ip}'
        for oct in ip.split('/')[0].split('.'):
            if int(oct) > 255:
                return False, 'Octeto > 255'
        if '/' in ip and int(ip.split('/')[1]) > 32:
            return False, 'Máscara > /32'
        return True, ''

    # ══════════════════════════════════════════════════════
    # MONTAR ARGS UFW
    # ══════════════════════════════════════════════════════

    def _montar_args(self, direcao, interface,
                     protocolo, ip, porta):
        """
        Monta string de argumentos para ufw.
        Cobre todos os casos: com/sem IP, com/sem interface,
        com/sem porta, entrada/saída.
        """
        porta     = str(porta).strip()    if porta     else ''
        interface = str(interface).strip() if interface else ''
        ip        = str(ip).strip()        if ip        else ''

        if protocolo in ('ambos', 'both', '', 'all'):
            proto_str = ''
        else:
            proto_str = protocolo.lower().strip()

        # ── SAÍDA sem interface, sem IP, só porta ─────────
        if direcao == 'out' and not interface and not ip and porta:
            if proto_str:
                return f'allow out {porta}/{proto_str}'
            else:
                return f'allow out {porta}'

        # ── SAÍDA sem interface, sem IP, sem porta ────────
        if direcao == 'out' and not interface and not ip and not porta:
            return 'allow out'

        # ── ENTRADA sem interface, sem IP, só porta ───────
        if direcao == 'in' and not interface and not ip and porta:
            if proto_str:
                return f'allow in {porta}/{proto_str}'
            else:
                return f'allow in {porta}'

        partes = ['allow', direcao]

        if interface:
            partes.append(f'on {interface}')

        if direcao == 'in':
            if ip:
                partes.append(f'from {ip}')
            else:
                partes.append('from any')
            if porta:
                dest = f'to any port {porta}'
                if proto_str:
                    dest += f' proto {proto_str}'
                partes.append(dest)
            elif proto_str:
                partes.append(f'proto {proto_str}')

        else:  # out
            partes.append('from any')
            if ip and porta:
                dest = f'to {ip} port {porta}'
                if proto_str:
                    dest += f' proto {proto_str}'
                partes.append(dest)
            elif ip:
                partes.append(f'to {ip}')
            elif porta:
                dest = f'to any port {porta}'
                if proto_str:
                    dest += f' proto {proto_str}'
                partes.append(dest)

        return ' '.join(partes)

    def _montar_regras_direcao(self, direcao, interface,
                                protocolo, ip, porta):
        """Expande 'ambos' em duas chamadas"""
        if direcao == 'ambos':
            return [
                self._montar_args(
                    'in', interface, protocolo, ip, porta
                ),
                self._montar_args(
                    'out', interface, protocolo, ip, porta
                )
            ]
        return [
            self._montar_args(
                direcao, interface, protocolo, ip, porta
            )
        ]

    # ══════════════════════════════════════════════════════
    # DEDUPLICAÇÃO
    # ══════════════════════════════════════════════════════

    def _regra_ja_existe(self, args):
        args_norm = args.strip().lower()
        for r in self.regras:
            if r.get('ufw_args', '').strip().lower() == args_norm:
                return True
        return False

    # ══════════════════════════════════════════════════════
    # ADICIONAR REGRA
    # ══════════════════════════════════════════════════════

    def adicionar_regra(self, dados,
                        categoria=None, editavel=True):
        with self._lock:
            try:
                nome      = str(dados.get('nome','')).strip()
                interface = str(dados.get('interface','')).strip()
                direcao   = str(dados.get('direcao','in')).strip()
                protocolo = str(dados.get('protocolo','tcp')).strip()
                ip        = str(dados.get('ip','')).strip()
                porta     = str(dados.get('porta','')).strip()
                cat       = categoria or self.CAT_USUARIO

                if not porta and not ip:
                    return {
                        'sucesso': False,
                        'erro': 'Informe Porta ou IP'
                    }

                if porta:
                    ok, err = self._validar_porta(porta)
                    if not ok:
                        return {'sucesso': False, 'erro': err}

                if ip:
                    ok, err = self._validar_ip(ip)
                    if not ok:
                        return {'sucesso': False, 'erro': err}

                lista_args = self._montar_regras_direcao(
                    direcao, interface, protocolo, ip, porta
                )

                ids_criados = []

                for idx_arg, args in enumerate(lista_args):
                    if self._regra_ja_existe(args):
                        logger.error(
                            f"Regra já existe (skip): {args}"
                        )
                        continue

                    res   = _exec_ufw(args)
                    saida = (
                        res.get('saida', '') +
                        res.get('erro', '')
                    )

                    if not res['sucesso']:
                        logger.error(
                            f"UFW rejeitou: '{args}' "
                            f"→ saida='{res.get('saida','')}' "
                            f"erro='{res.get('erro','')}'"
                        )
                        continue

                    if direcao == 'ambos':
                        dir_real = 'in' if idx_arg == 0 else 'out'
                    else:
                        dir_real = direcao

                    rid   = str(uuid.uuid4())[:8]
                    regra = {
                        'id':          rid,
                        'nome':        nome,
                        'categoria':   cat,
                        'interface':   interface,
                        'direcao':     dir_real,
                        'protocolo':   protocolo,
                        'ip':          ip,
                        'porta':       porta,
                        'ufw_args':    args,
                        'delete_args': f'delete {args}',
                        'pausada':     False,
                        'editavel':    editavel,
                        'timestamp':   datetime.now().isoformat()
                    }
                    self.regras.append(regra)
                    ids_criados.append(rid)

                if ids_criados:
                    self._salvar()
                    return {
                        'sucesso': True,
                        'ids':     ids_criados
                    }

                return {
                    'sucesso': True,
                    'ids':     [],
                    'aviso':   'Regras já existiam'
                }

            except Exception as e:
                logger.error(f"adicionar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # REMOVER
    # ══════════════════════════════════════════════════════

    def remover_regra(self, rid):
        with self._lock:
            try:
                for i, r in enumerate(self.regras):
                    if r.get('id') == rid:
                        if not r.get('editavel', True):
                            return {
                                'sucesso': False,
                                'erro': 'Regra não editável'
                            }
                        if not r.get('pausada', False):
                            da = r.get('delete_args', '')
                            if da:
                                _exec_ufw(f'--force {da}')
                        self.regras.pop(i)
                        self._salvar()
                        return {'sucesso': True}
                return {
                    'sucesso': False,
                    'erro': 'Regra não encontrada'
                }
            except Exception as e:
                logger.error(f"remover_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    def remover_regras_por_categoria(self, categoria):
        with self._lock:
            try:
                para_rem = [
                    r for r in self.regras
                    if r.get('categoria') == categoria
                ]
                for r in para_rem:
                    if not r.get('pausada', False):
                        da = r.get('delete_args', '')
                        if da:
                            _exec_ufw(f'--force {da}')
                self.regras = [
                    r for r in self.regras
                    if r.get('categoria') != categoria
                ]
                self._salvar()
            except Exception as e:
                logger.error(
                    f"remover_regras_por_categoria: {e}"
                )

    # ══════════════════════════════════════════════════════
    # PAUSAR / REATIVAR
    # ══════════════════════════════════════════════════════

    def pausar_regra(self, rid):
        with self._lock:
            try:
                for r in self.regras:
                    if r.get('id') == rid:
                        if not r.get('editavel', True):
                            return {
                                'sucesso': False,
                                'erro': 'Regra não editável'
                            }
                        da = r.get('delete_args', '')
                        if da:
                            res   = _exec_ufw(f'--force {da}')
                            saida = (
                                res.get('saida','') +
                                res.get('erro','')
                            )
                            if not (
                                res['sucesso'] or
                                'Rule deleted' in saida or
                                'Deleting' in saida
                            ):
                                return {
                                    'sucesso': False,
                                    'erro': 'Falha ao pausar'
                                }
                        r['pausada']    = True
                        r['pausada_em'] = datetime.now().isoformat()
                        self._salvar()
                        return {'sucesso': True}
                return {
                    'sucesso': False,
                    'erro': 'Regra não encontrada'
                }
            except Exception as e:
                logger.error(f"pausar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    def reativar_regra(self, rid):
        with self._lock:
            try:
                for r in self.regras:
                    if r.get('id') == rid:
                        args = r.get('ufw_args', '')
                        if not args:
                            return {
                                'sucesso': False,
                                'erro': 'Dados incompletos'
                            }
                        res   = _exec_ufw(args)
                        saida = (
                            res.get('saida','') +
                            res.get('erro','')
                        )
                        if (res['sucesso'] or
                                'Rule added' in saida or
                                'Skipping' in saida):
                            r['pausada'] = False
                            r.pop('pausada_em', None)
                            self._salvar()
                            return {'sucesso': True}
                        return {
                            'sucesso': False,
                            'erro': res.get('erro','Erro')
                        }
                return {
                    'sucesso': False,
                    'erro': 'Não encontrada'
                }
            except Exception as e:
                logger.error(f"reativar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # EDITAR
    # ══════════════════════════════════════════════════════

    def editar_regra(self, dados):
        with self._lock:
            try:
                rid = dados.get('id','')
                for i, r in enumerate(self.regras):
                    if r.get('id') == rid:
                        if not r.get('editavel', True):
                            return {
                                'sucesso': False,
                                'erro': 'Regra não editável'
                            }
                        if not r.get('pausada', False):
                            da = r.get('delete_args','')
                            if da:
                                _exec_ufw(f'--force {da}')
                        self.regras.pop(i)
                        self._salvar()
                        return self.adicionar_regra(dados)
                return {
                    'sucesso': False,
                    'erro': 'Não encontrada'
                }
            except Exception as e:
                logger.error(f"editar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # INTERFACE DO SISTEMA (timer 5 min)
    # ══════════════════════════════════════════════════════

    def iniciar_mudanca_interface(self, interface):
        try:
            anterior = self._config.get(
                'interface_sistema', ''
            )
            self._config.update({
                'interface_sistema':    interface,
                'interface_pendente':   interface,
                'interface_anterior':   anterior,
                'pendente_iniciado_em': datetime.now().isoformat(),
                'pendente_confirmado':  False
            })
            self._salvar_config()
            self.garantir_regra_sistema()

            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(
                300, self._reverter_interface
            )
            self._timer.daemon = True
            self._timer.start()

            return {
                'sucesso': True,
                'mensagem': (
                    f'Interface alterada para '
                    f'"{interface or "todas"}". '
                    f'Confirme em 5 minutos!'
                ),
                'tempo': 300
            }
        except Exception as e:
            logger.error(f"iniciar_mudanca_interface: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def confirmar_mudanca_interface(self):
        try:
            if self._config.get('pendente_confirmado', True):
                return {
                    'sucesso': False,
                    'erro': 'Nenhuma mudança pendente'
                }
            if self._timer:
                self._timer.cancel()
                self._timer = None
            self._config.update({
                'pendente_confirmado': True
            })
            for k in ['interface_anterior',
                      'interface_pendente',
                      'pendente_iniciado_em']:
                self._config.pop(k, None)
            self._salvar_config()
            return {
                'sucesso': True,
                'mensagem': 'Interface confirmada!'
            }
        except Exception as e:
            logger.error(f"confirmar_mudanca_interface: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _reverter_interface(self):
        try:
            anterior = self._config.get('interface_anterior','')
            self._config.update({
                'interface_sistema':   anterior,
                'pendente_confirmado': True
            })
            for k in ['interface_pendente',
                      'interface_anterior',
                      'pendente_iniciado_em']:
                self._config.pop(k, None)
            self._salvar_config()
            self.garantir_regra_sistema()
            logger.error(
                "Interface revertida (timeout 5 min)"
            )
        except Exception as e:
            logger.error(f"_reverter_interface: {e}")

    def status_mudanca_interface(self):
        try:
            pendente   = self._config.get('interface_pendente')
            iniciado   = self._config.get('pendente_iniciado_em')
            confirmado = self._config.get(
                'pendente_confirmado', True
            )

            if confirmado or not pendente:
                return {
                    'pendente': False,
                    'interface_atual': self._config.get(
                        'interface_sistema', ''
                    )
                }

            restante = 0
            if iniciado:
                dt      = datetime.fromisoformat(iniciado)
                elapsed = (datetime.now() - dt).total_seconds()
                restante = max(0, 300 - int(elapsed))

            return {
                'pendente':           True,
                'interface_pendente': pendente,
                'interface_anterior': self._config.get(
                    'interface_anterior', ''
                ),
                'restante':       restante,
                'interface_atual': self._config.get(
                    'interface_sistema', ''
                )
            }
        except Exception as e:
            logger.error(f"status_mudanca_interface: {e}")
            return {'pendente': False}

    # ══════════════════════════════════════════════════════
    # GERENCIAMENTO AUTOMÁTICO DE VPN
    # ══════════════════════════════════════════════════════

    def configurar_vpn_saida_ativa(self, info_vpn):
        try:
            with self._lock:
                self.remover_regras_por_categoria(
                    self.CAT_VPN_AUTO
                )

                tunel_ativo = self._detectar_tunel_vpn_ativo()
                if not tunel_ativo:
                    logger.error("Túnel VPN não detectado")
                    return {
                        'sucesso': False,
                        'erro': 'Túnel VPN não detectado'
                    }

                regras_saida = [
                    r for r in self.regras
                    if (r.get('direcao') == 'out' and
                        r.get('categoria') == self.CAT_USUARIO
                        and not r.get('pausada', False))
                ]

                ids_criados = []

                for regra_orig in regras_saida:
                    nova_regra = {
                        'nome': (
                            f"VPN-Auto: "
                            f"{regra_orig.get('nome', 'Regra')}"
                        ),
                        'interface': tunel_ativo,
                        'direcao':   'out',
                        'protocolo': regra_orig.get(
                            'protocolo', 'tcp'
                        ),
                        'ip':    regra_orig.get('ip', ''),
                        'porta': regra_orig.get('porta', '')
                    }
                    resultado = self.adicionar_regra(
                        nova_regra,
                        categoria=self.CAT_VPN_AUTO,
                        editavel=False
                    )
                    if resultado.get('sucesso'):
                        ids_criados.extend(
                            resultado.get('ids', [])
                        )

                if not regras_saida:
                    regras_basicas = [
                        {
                            'nome':      'VPN-Auto: HTTP',
                            'porta':     '80',
                            'protocolo': 'tcp'
                        },
                        {
                            'nome':      'VPN-Auto: HTTPS',
                            'porta':     '443',
                            'protocolo': 'tcp'
                        },
                        {
                            'nome':      'VPN-Auto: DNS',
                            'porta':     '53',
                            'protocolo': 'udp'
                        },
                        {
                            'nome':      'VPN-Auto: DNS-TCP',
                            'porta':     '53',
                            'protocolo': 'tcp'
                        },
                    ]
                    for rb in regras_basicas:
                        rb.update({
                            'interface': tunel_ativo,
                            'direcao':   'out',
                            'ip':        ''
                        })
                        resultado = self.adicionar_regra(
                            rb,
                            categoria=self.CAT_VPN_AUTO,
                            editavel=False
                        )
                        if resultado.get('sucesso'):
                            ids_criados.extend(
                                resultado.get('ids', [])
                            )

                self._config['vpn_saida_ativa'] = {
                    'tunel':          tunel_ativo,
                    'configurado_em': datetime.now().isoformat(),
                    'regras_criadas': len(ids_criados)
                }
                self._salvar_config()

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'VPN configurada: '
                        f'{len(ids_criados)} regras automáticas'
                    ),
                    'tunel':          tunel_ativo,
                    'regras_criadas': len(ids_criados)
                }

        except Exception as e:
            logger.error(f"configurar_vpn_saida_ativa: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def configurar_vpn_acesso_ativa(self, info_vpn):
        try:
            with self._lock:
                tunel_acesso = self._detectar_tunel_vpn_acesso()
                if not tunel_acesso:
                    return {
                        'sucesso': False,
                        'erro': 'Túnel VPN de acesso não detectado'
                    }

                portas_acesso = info_vpn.get(
                    'portas', [str(PORTA_SISTEMA)]
                )
                ids_criados = []

                for porta in portas_acesso:
                    for protocolo in ['tcp', 'udp']:
                        regra_entrada = {
                            'nome': (
                                f'VPN-Acesso: '
                                f'Entrada {porta}/{protocolo}'
                            ),
                            'interface': tunel_acesso,
                            'direcao':   'in',
                            'protocolo': protocolo,
                            'ip':        '',
                            'porta':     str(porta)
                        }
                        resultado = self.adicionar_regra(
                            regra_entrada,
                            categoria=self.CAT_VPN_AUTO,
                            editavel=False
                        )
                        if resultado.get('sucesso'):
                            ids_criados.extend(
                                resultado.get('ids', [])
                            )

                regras_saida_basicas = [
                    {
                        'nome':      'VPN-Acesso: Saída HTTP',
                        'porta':     '80',
                        'protocolo': 'tcp'
                    },
                    {
                        'nome':      'VPN-Acesso: Saída HTTPS',
                        'porta':     '443',
                        'protocolo': 'tcp'
                    },
                    {
                        'nome':      'VPN-Acesso: Saída DNS',
                        'porta':     '53',
                        'protocolo': 'udp'
                    },
                ]
                for rs in regras_saida_basicas:
                    rs.update({
                        'interface': tunel_acesso,
                        'direcao':   'out',
                        'ip':        ''
                    })
                    resultado = self.adicionar_regra(
                        rs,
                        categoria=self.CAT_VPN_AUTO,
                        editavel=False
                    )
                    if resultado.get('sucesso'):
                        ids_criados.extend(
                            resultado.get('ids', [])
                        )

                self._config['vpn_acesso_ativa'] = {
                    'tunel':          tunel_acesso,
                    'configurado_em': datetime.now().isoformat(),
                    'regras_criadas': len(ids_criados),
                    'portas':         portas_acesso
                }
                self._salvar_config()

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'VPN de acesso configurada: '
                        f'{len(ids_criados)} regras'
                    ),
                    'tunel':          tunel_acesso,
                    'regras_criadas': len(ids_criados)
                }

        except Exception as e:
            logger.error(f"configurar_vpn_acesso_ativa: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_configuracao_vpn(self, tipo='saida'):
        try:
            with self._lock:
                if tipo in ('saida', 'todas'):
                    self._config.pop('vpn_saida_ativa', None)
                if tipo in ('acesso', 'todas'):
                    self._config.pop('vpn_acesso_ativa', None)
                self.remover_regras_por_categoria(
                    self.CAT_VPN_AUTO
                )
                self._salvar_config()
                return {
                    'sucesso': True,
                    'mensagem': (
                        f'Configurações VPN {tipo} removidas'
                    )
                }
        except Exception as e:
            logger.error(f"remover_configuracao_vpn: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _detectar_tunel_vpn_ativo(self):
        try:
            for tunel in ['tun0', 'tun1', 'tun2']:
                r = subprocess.run(
                    f'ip link show {tunel}',
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if r.returncode == 0 and 'UP' in r.stdout:
                    r_ip = subprocess.run(
                        f'ip addr show {tunel}',
                        shell=True,
                        capture_output=True,
                        text=True
                    )
                    if (r_ip.returncode == 0 and
                            'inet ' in r_ip.stdout):
                        return tunel
            return None
        except Exception as e:
            logger.error(f"_detectar_tunel_vpn_ativo: {e}")
            return None

    def _detectar_tunel_vpn_acesso(self):
        try:
            for tunel in ['tap0', 'tun10', 'tun11']:
                r = subprocess.run(
                    f'ip link show {tunel}',
                    shell=True,
                    capture_output=True,
                    text=True
                )
                if r.returncode == 0:
                    return tunel

            r = subprocess.run(
                'pgrep -f "openvpn.*server"',
                shell=True,
                capture_output=True,
                text=True
            )
            if r.returncode == 0:
                vpn_saida = self._config.get(
                    'vpn_saida_ativa', {}
                )
                return 'tun1' if vpn_saida else 'tun0'

            return None
        except Exception as e:
            logger.error(f"_detectar_tunel_vpn_acesso: {e}")
            return None

    def obter_status_vpn_firewall(self):
        try:
            regras_vpn_auto = [
                r for r in self.regras
                if r.get('categoria') == self.CAT_VPN_AUTO
            ]
            return {
                'vpn_saida_ativa':    self._config.get(
                    'vpn_saida_ativa'
                ),
                'vpn_acesso_ativa':   self._config.get(
                    'vpn_acesso_ativa'
                ),
                'regras_automaticas': len(regras_vpn_auto),
                'tuneis_detectados': {
                    'saida':  self._detectar_tunel_vpn_ativo(),
                    'acesso': self._detectar_tunel_vpn_acesso()
                }
            }
        except Exception as e:
            logger.error(f"obter_status_vpn_firewall: {e}")
            return {}

    # ══════════════════════════════════════════════════════
    # HELPERS PÚBLICOS PARA OUTROS MÓDULOS
    # ══════════════════════════════════════════════════════

    def adicionar_regra_automatica(self, chave_nome,
                                    dados, categoria):
        nome_busca = dados.get('nome', chave_nome)
        for r in self.regras:
            if (r.get('nome') == nome_busca and
                    r.get('categoria') == categoria):
                return {
                    'sucesso': True,
                    'aviso': f'Regra "{nome_busca}" já existe'
                }

        dados_com_nome = dict(dados)
        if 'nome' not in dados_com_nome:
            dados_com_nome['nome'] = chave_nome

        return self.adicionar_regra(
            dados_com_nome,
            categoria=categoria,
            editavel=False
        )

    def remover_regras_tor(self, prefixo_nome):
        with self._lock:
            try:
                para_rem = [
                    r for r in self.regras
                    if (r.get('categoria') == self.CAT_TOR and
                        r.get('nome','').startswith(prefixo_nome))
                ]
                for r in para_rem:
                    if not r.get('pausada', False):
                        da = r.get('delete_args','')
                        if da:
                            _exec_ufw(f'--force {da}')
                self.regras = [
                    r for r in self.regras
                    if r not in para_rem
                ]
                self._salvar()
            except Exception as e:
                logger.error(f"remover_regras_tor: {e}")

    def remover_regras_vpn(self, prefixo_nome):
        with self._lock:
            try:
                para_rem = [
                    r for r in self.regras
                    if (r.get('categoria') == self.CAT_VPN and
                        r.get('nome','').startswith(prefixo_nome))
                ]
                for r in para_rem:
                    if not r.get('pausada', False):
                        da = r.get('delete_args','')
                        if da:
                            _exec_ufw(f'--force {da}')
                self.regras = [
                    r for r in self.regras
                    if r not in para_rem
                ]
                self._salvar()
            except Exception as e:
                logger.error(f"remover_regras_vpn: {e}")

    # ══════════════════════════════════════════════════════
    # DIAGNÓSTICO
    # ══════════════════════════════════════════════════════

    def diagnosticar_regras_tor(self):
        problemas  = []
        regras_tor = [
            r for r in self.regras
            if r.get('categoria') == self.CAT_TOR
        ]
        nomes_tor = {r.get('nome','') for r in regras_tor}

        portas_obrig = [
            (
                'Tor:infra:saida:9001',
                'Saída TCP 9001 (OR port)'
            ),
            (
                'Tor:infra:saida:9030',
                'Saída TCP 9030 (Dir port)'
            ),
            ('Tor:infra:saida:443',  'Saída TCP 443'),
            ('Tor:infra:saida:80',   'Saída TCP 80'),
            ('Tor:infra:saida:dns',  'Saída UDP 53 (DNS)'),
            (
                'Tor:infra:lo:in:9050',
                'Loopback in 9050 (SOCKS)'
            ),
            (
                'Tor:infra:lo:out:9050',
                'Loopback out 9050'
            ),
        ]

        for nome, desc in portas_obrig:
            if nome not in nomes_tor:
                problemas.append({
                    'nome': nome,
                    'desc': desc,
                    'tipo': 'ausente'
                })

        return problemas

    def diagnosticar_regras_vpn(self):
        problemas  = []
        vpn_saida  = self._config.get('vpn_saida_ativa')
        vpn_acesso = self._config.get('vpn_acesso_ativa')

        regras_vpn_auto = [
            r for r in self.regras
            if r.get('categoria') == self.CAT_VPN_AUTO
        ]

        if vpn_saida and not regras_vpn_auto:
            problemas.append({
                'nome': 'VPN_SAIDA_SEM_REGRAS',
                'desc': (
                    'VPN de saída ativa mas '
                    'sem regras automáticas'
                ),
                'tipo': 'configuracao'
            })

        if vpn_acesso and not regras_vpn_auto:
            problemas.append({
                'nome': 'VPN_ACESSO_SEM_REGRAS',
                'desc': (
                    'VPN de acesso ativa mas '
                    'sem regras automáticas'
                ),
                'tipo': 'configuracao'
            })

        tunel_saida  = self._detectar_tunel_vpn_ativo()
        tunel_acesso = self._detectar_tunel_vpn_acesso()

        if vpn_saida and not tunel_saida:
            problemas.append({
                'nome': 'TUNEL_SAIDA_NAO_DETECTADO',
                'desc': (
                    'VPN de saída configurada mas '
                    'túnel não detectado'
                ),
                'tipo': 'rede'
            })

        if vpn_acesso and not tunel_acesso:
            problemas.append({
                'nome': 'TUNEL_ACESSO_NAO_DETECTADO',
                'desc': (
                    'VPN de acesso configurada mas '
                    'túnel não detectado'
                ),
                'tipo': 'rede'
            })

        return problemas
