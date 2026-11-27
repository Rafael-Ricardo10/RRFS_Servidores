#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
firewall_ufw.py - RRFS Servidores v2.4
v2.4:
  - Removida toda a lógica de VPN (conexao.py foi descontinuado);
    regras legadas 'vpn'/'vpn_auto' são limpas automaticamente
  - Nova categoria CAT_TOX (acesso remoto via Tox)
  - _exec_ufw sem shell (shlex) -> sem injeção de comando
  - Interface/protocolo validados
  - Lock reentrante (editar_regra travava a si mesmo)
  - Regras automáticas sem porta/IP permitidas (ex.: saída UDP livre)
  - 'out' sem IP/porta agora respeita o protocolo
  - Regra do sistema: ao trocar interface, a regra antiga é removida do UFW
  - Regras automáticas 'sistema' (DNS) podem ser removidas por outros módulos
  - remover_regras_prefixo() genérico; diagnóstico Tor corrigido
"""

import os
import re
import json
import uuid
import shlex
import logging
import threading
import subprocess
from datetime import datetime

logger = logging.getLogger('RRFS.UFW')

PORTA_SISTEMA = 2000
ID_REGRA_SISTEMA = 'sistema_porta_2000'
RE_IFACE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
PROTOCOLOS_OK = ('tcp', 'udp', 'ambos', 'both', 'all', '')


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
            [ufw] + shlex.split(args),
            capture_output=True, text=True, timeout=timeout,
            env={
                **os.environ,
                'PATH': ('/usr/local/sbin:/usr/local/bin:'
                         '/usr/sbin:/usr/bin:/sbin:/bin'),
                'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8'
            }
        )
        saida = r.stdout.strip()
        erro  = r.stderr.strip()
        ok    = (
            r.returncode == 0 or
            'Rule added' in saida or 'Rules updated' in saida or
            'Skipping' in saida or 'already exists' in saida or
            'Rule added' in erro or 'Rules updated' in erro
        )
        return {'sucesso': ok, 'saida': saida,
                'erro': erro, 'codigo': r.returncode}
    except subprocess.TimeoutExpired:
        logger.error(f"UFW timeout: {args}")
        return {'sucesso': False, 'saida': '',
                'erro': 'Timeout', 'codigo': -1}
    except Exception as e:
        logger.error(f"_exec_ufw '{args}': {e}")
        return {'sucesso': False, 'saida': '',
                'erro': str(e), 'codigo': -1}


class FirewallUFW:

    CAT_USUARIO = 'usuario'
    CAT_SISTEMA = 'sistema'
    CAT_TOR     = 'tor'
    CAT_TOX     = 'tox'

    _CATS_LEGADAS = ('vpn', 'vpn_auto')

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
        self._timer    = None
        self._lock     = threading.RLock()
        self._carregar()
        self._carregar_config()

    # ══════════════════════════════════════════════════════
    # PERSISTÊNCIA
    # ══════════════════════════════════════════════════════

    def _carregar(self):
        try:
            if os.path.exists(self._path):
                with open(self._path, 'r', encoding='utf-8') as f:
                    self.regras = json.load(f)
        except Exception as e:
            logger.error(f"carregar regras: {e}")
            self.regras = []

    def _salvar(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, 'w', encoding='utf-8') as f:
                json.dump(self.regras, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"salvar regras: {e}")

    def _carregar_config(self):
        try:
            if os.path.exists(self._cfg_path):
                with open(self._cfg_path, 'r', encoding='utf-8') as f:
                    self._config = json.load(f)
        except Exception as e:
            logger.error(f"carregar config ufw: {e}")
            self._config = {}

    def _salvar_config(self):
        try:
            os.makedirs(os.path.dirname(self._cfg_path), exist_ok=True)
            with open(self._cfg_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"salvar config ufw: {e}")

    # ══════════════════════════════════════════════════════
    # INICIALIZAÇÃO
    # ══════════════════════════════════════════════════════

    def inicializar(self):
        try:
            self._limpar_legado_vpn()

            _exec_ufw('default deny incoming')
            _exec_ufw('default deny outgoing')
            _exec_ufw('--force enable')

            for r in self.regras:
                if (not r.get('pausada') and
                        r.get('id') != ID_REGRA_SISTEMA):
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

    def _limpar_legado_vpn(self):
        """Remove regras e config das VPNs (conexao.py descontinuado)."""
        try:
            with self._lock:
                legadas = [r for r in self.regras
                           if r.get('categoria') in self._CATS_LEGADAS]
                for r in legadas:
                    if not r.get('pausada', False):
                        da = r.get('delete_args', '')
                        if da:
                            _exec_ufw(f'--force {da}')
                if legadas:
                    self.regras = [
                        r for r in self.regras
                        if r.get('categoria') not in self._CATS_LEGADAS
                    ]
                    self._salvar()
                mudou = False
                for k in ('vpn_saida_ativa', 'vpn_acesso_ativa'):
                    if k in self._config:
                        self._config.pop(k)
                        mudou = True
                if mudou:
                    self._salvar_config()
        except Exception as e:
            logger.error(f"_limpar_legado_vpn: {e}")

    def garantir_regra_sistema(self):
        try:
            with self._lock:
                # remove do UFW a regra antiga (interface pode ter mudado)
                for r in self.regras:
                    if r.get('id') == ID_REGRA_SISTEMA:
                        da = r.get('delete_args', '')
                        if da:
                            _exec_ufw(f'--force {da}')
                self.regras = [
                    r for r in self.regras
                    if r.get('id') != ID_REGRA_SISTEMA
                ]
                interface = self._config.get('interface_sistema', '')
                if interface and not RE_IFACE.match(interface):
                    interface = ''
                args = self._montar_args_porta_sistema(interface)
                res  = _exec_ufw(args)
                if not res['sucesso']:
                    logger.error(
                        f"garantir_regra_sistema falhou: {res['erro']}"
                    )
                self.regras.insert(0, {
                    'id':          ID_REGRA_SISTEMA,
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
                })
                self._salvar()
        except Exception as e:
            logger.error(f"garantir_regra_sistema: {e}")

    def _montar_args_porta_sistema(self, interface=''):
        if interface:
            return (f'allow in on {interface} '
                    f'to any port {PORTA_SISTEMA} proto tcp')
        return f'allow in to any port {PORTA_SISTEMA} proto tcp'

    # ══════════════════════════════════════════════════════
    # STATUS
    # ══════════════════════════════════════════════════════

    def obter_status(self):
        try:
            r   = _exec_ufw('status verbose')
            txt = r.get('saida', '')
            return {
                'ativo':            'status: active' in txt.lower(),
                'politica_entrada': self._pol(txt, 'incoming'),
                'politica_saida':   self._pol(txt, 'outgoing'),
                'texto':            txt
            }
        except Exception as e:
            logger.error(f"obter_status ufw: {e}")
            return {'ativo': False, 'politica_entrada': 'unknown',
                    'politica_saida': 'unknown', 'texto': ''}

    def _pol(self, txt, termo):
        t = txt.lower()
        if f'deny ({termo})'  in t:
            return 'deny'
        if f'allow ({termo})' in t:
            return 'allow'
        return 'unknown'

    def listar_regras_salvas(self):
        return self.regras

    # ══════════════════════════════════════════════════════
    # INTERFACES
    # ══════════════════════════════════════════════════════

    def obter_interfaces_disponiveis(self):
        """Todas as interfaces: any, lo, físicas, bridges, docker, etc."""
        try:
            interfaces = [
                {'nome': '', 'label': 'Qualquer interface (any)',
                 'tipo': 'any', 'ativa': True, 'ip': '', 'mac': ''},
                {'nome': 'lo', 'label': 'lo — Loopback (127.0.0.1)',
                 'tipo': 'loopback', 'ativa': True,
                 'ip': '127.0.0.1', 'mac': ''},
            ]
            r = subprocess.run(['ip', '-o', 'link', 'show'],
                               capture_output=True, text=True)
            if r.returncode != 0:
                return interfaces

            for linha in r.stdout.splitlines():
                m = re.match(r'\d+:\s+(\S+?)(@\S+)?:', linha)
                if not m:
                    continue
                nome = m.group(1).strip()
                if nome == 'lo':
                    continue
                tipo = self._detectar_tipo_interface(nome)
                ip   = self._obter_ip_interface(nome)
                interfaces.append({
                    'nome':  nome,
                    'label': self._label_interface(nome, tipo, ip),
                    'tipo':  tipo,
                    'ativa': ('UP' in linha and 'LOWER_UP' in linha),
                    'ip':    ip,
                    'mac':   self._obter_mac_interface(nome),
                })

            ordem = {'any': 0, 'loopback': 1, 'ethernet': 2, 'wifi': 3,
                     'vpn_tunnel': 4, 'wireguard': 5, 'bridge': 6,
                     'docker': 7, 'veth': 8, 'vlan': 9, 'virtual': 10,
                     'outro': 11}
            interfaces.sort(
                key=lambda x: (ordem.get(x['tipo'], 99), x['nome'])
            )
            return interfaces
        except Exception as e:
            logger.error(f"obter_interfaces_disponiveis: {e}")
            return []

    def _detectar_tipo_interface(self, nome):
        if nome.startswith(('tun', 'tap')):
            return 'vpn_tunnel'
        if nome.startswith('wg'):
            return 'wireguard'
        if nome.startswith('docker'):
            return 'docker'
        if nome.startswith('veth'):
            return 'veth'
        if nome.startswith(('virbr', 'br-')):
            return 'bridge'
        if nome.startswith('br') and os.path.exists(
                f'/sys/class/net/{nome}/bridge'):
            return 'bridge'
        if re.match(r'.+\.\d+$', nome):
            return 'vlan'
        if nome.startswith(('dummy', 'sit', 'ip6tnl')):
            return 'virtual'
        sysfs = f'/sys/class/net/{nome}'
        if (os.path.exists(f'{sysfs}/wireless') or
                os.path.exists(f'{sysfs}/phy80211')):
            return 'wifi'
        if nome.startswith(('wlan', 'wlp', 'wlx', 'wls', 'ath',
                            'ra', 'rausb')):
            return 'wifi'
        if os.path.exists(f'{sysfs}/device'):
            return 'ethernet'
        if nome.startswith(('eth', 'enp', 'ens', 'eno', 'enx',
                            'lan', 'wan', 'em')):
            return 'ethernet'
        return 'outro'

    def _label_interface(self, nome, tipo, ip=''):
        ip_str = f' ({ip})' if ip else ''
        nomes = {'ethernet': 'Ethernet', 'wifi': 'WiFi',
                 'vpn_tunnel': 'Túnel', 'wireguard': 'WireGuard',
                 'bridge': 'Bridge', 'docker': 'Docker',
                 'veth': 'Container', 'vlan': 'VLAN',
                 'virtual': 'Virtual'}
        if tipo in nomes:
            return f'{nome} — {nomes[tipo]}{ip_str}'
        return f'{nome}{ip_str}'

    def _obter_ip_interface(self, nome):
        try:
            if not RE_IFACE.match(nome):
                return ''
            r = subprocess.run(['ip', '-4', 'addr', 'show', nome],
                               capture_output=True, text=True)
            if r.returncode == 0:
                m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', r.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass
        return ''

    def _obter_mac_interface(self, nome):
        try:
            p = f'/sys/class/net/{nome}/address'
            if os.path.exists(p):
                with open(p) as f:
                    mac = f.read().strip()
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
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$', ip):
            return False, f'IP inválido: {ip}'
        for octeto in ip.split('/')[0].split('.'):
            if int(octeto) > 255:
                return False, 'Octeto > 255'
        if '/' in ip and int(ip.split('/')[1]) > 32:
            return False, 'Máscara > /32'
        return True, ''

    # ══════════════════════════════════════════════════════
    # MONTAR ARGS UFW
    # ══════════════════════════════════════════════════════

    def _montar_args(self, direcao, interface, protocolo, ip, porta):
        porta     = str(porta).strip()     if porta     else ''
        interface = str(interface).strip() if interface else ''
        ip        = str(ip).strip()        if ip        else ''
        proto_str = ('' if protocolo in ('ambos', 'both', '', 'all')
                     else protocolo.lower().strip())

        # atalhos simples (sem interface e sem IP)
        if not interface and not ip and porta:
            return (f'allow {direcao} {porta}/{proto_str}'
                    if proto_str else f'allow {direcao} {porta}')

        partes = ['allow', direcao]
        if interface:
            partes.append(f'on {interface}')

        if direcao == 'in':
            partes.append(f'from {ip}' if ip else 'from any')
            dest = 'to any'
            if porta:
                dest += f' port {porta}'
            if proto_str:
                dest += f' proto {proto_str}'
            if dest != 'to any':
                partes.append(dest)
        else:
            partes.append('from any')
            dest = f'to {ip}' if ip else 'to any'
            if porta:
                dest += f' port {porta}'
            if proto_str:
                dest += f' proto {proto_str}'
            if dest != 'to any' or interface or proto_str:
                partes.append(dest)

        return ' '.join(partes)

    def _montar_regras_direcao(self, direcao, interface,
                               protocolo, ip, porta):
        if direcao == 'ambos':
            return [
                self._montar_args('in', interface, protocolo, ip, porta),
                self._montar_args('out', interface, protocolo, ip, porta)
            ]
        return [self._montar_args(direcao, interface,
                                  protocolo, ip, porta)]

    def _regra_ja_existe(self, args):
        a = args.strip().lower()
        return any(r.get('ufw_args', '').strip().lower() == a
                   for r in self.regras)

    # ══════════════════════════════════════════════════════
    # ADICIONAR REGRA
    # ══════════════════════════════════════════════════════

    def adicionar_regra(self, dados, categoria=None, editavel=True):
        with self._lock:
            try:
                nome      = str(dados.get('nome', '')).strip()
                interface = str(dados.get('interface', '')).strip()
                direcao   = str(dados.get('direcao', 'in')).strip()
                protocolo = str(dados.get('protocolo', 'tcp')
                                ).strip().lower()
                ip        = str(dados.get('ip', '')).strip()
                porta     = str(dados.get('porta', '')).strip()
                cat       = categoria or self.CAT_USUARIO

                if direcao not in ('in', 'out', 'ambos'):
                    return {'sucesso': False,
                            'erro': 'Direção inválida'}
                if protocolo not in PROTOCOLOS_OK:
                    return {'sucesso': False,
                            'erro': 'Protocolo inválido'}
                if interface and not RE_IFACE.match(interface):
                    return {'sucesso': False,
                            'erro': 'Interface inválida'}

                # regras de usuário precisam de alvo; as automáticas
                # (tor/tox/sistema) podem ser "saída UDP livre", etc.
                if not porta and not ip and cat == self.CAT_USUARIO:
                    return {'sucesso': False,
                            'erro': 'Informe Porta ou IP'}
                if porta:
                    ok, err = self._validar_porta(porta)
                    if not ok:
                        return {'sucesso': False, 'erro': err}
                if ip:
                    ok, err = self._validar_ip(ip)
                    if not ok:
                        return {'sucesso': False, 'erro': err}

                lista_args  = self._montar_regras_direcao(
                    direcao, interface, protocolo, ip, porta
                )
                ids_criados = []

                for idx_arg, args in enumerate(lista_args):
                    if self._regra_ja_existe(args):
                        continue
                    res = _exec_ufw(args)
                    if not res['sucesso']:
                        logger.error(
                            f"UFW rejeitou: '{args}' → "
                            f"saida='{res.get('saida', '')}' "
                            f"erro='{res.get('erro', '')}'"
                        )
                        continue

                    dir_real = (('in' if idx_arg == 0 else 'out')
                                if direcao == 'ambos' else direcao)
                    rid = str(uuid.uuid4())[:8]
                    self.regras.append({
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
                    })
                    ids_criados.append(rid)

                if ids_criados:
                    self._salvar()
                    return {'sucesso': True, 'ids': ids_criados}
                return {'sucesso': True, 'ids': [],
                        'aviso': 'Regras já existiam'}
            except Exception as e:
                logger.error(f"adicionar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # REMOVER
    # ══════════════════════════════════════════════════════

    def _removivel(self, r):
        """Editáveis, ou regras automáticas 'sistema' (ex.: DNS).
        A regra da porta 2000 nunca é removível."""
        if r.get('id') == ID_REGRA_SISTEMA:
            return False
        return (r.get('editavel', True) or
                r.get('categoria') == self.CAT_SISTEMA)

    def remover_regra(self, rid):
        with self._lock:
            try:
                for i, r in enumerate(self.regras):
                    if r.get('id') == rid:
                        if not self._removivel(r):
                            return {'sucesso': False,
                                    'erro': 'Regra não editável'}
                        if not r.get('pausada', False):
                            da = r.get('delete_args', '')
                            if da:
                                _exec_ufw(f'--force {da}')
                        self.regras.pop(i)
                        self._salvar()
                        return {'sucesso': True}
                return {'sucesso': False,
                        'erro': 'Regra não encontrada'}
            except Exception as e:
                logger.error(f"remover_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    def _remover_lista(self, para_rem):
        for r in para_rem:
            if not r.get('pausada', False):
                da = r.get('delete_args', '')
                if da:
                    _exec_ufw(f'--force {da}')
        ids = {id(r) for r in para_rem}
        self.regras = [r for r in self.regras if id(r) not in ids]
        self._salvar()

    def remover_regras_por_categoria(self, categoria):
        with self._lock:
            try:
                self._remover_lista([
                    r for r in self.regras
                    if r.get('categoria') == categoria
                ])
            except Exception as e:
                logger.error(f"remover_regras_por_categoria: {e}")

    def remover_regras_prefixo(self, categoria, prefixo):
        """Remove regras da categoria cujo nome começa com o prefixo."""
        with self._lock:
            try:
                self._remover_lista([
                    r for r in self.regras
                    if (r.get('categoria') == categoria and
                        r.get('nome', '').startswith(prefixo))
                ])
            except Exception as e:
                logger.error(f"remover_regras_prefixo: {e}")

    def remover_regras_tor(self, prefixo_nome, exato=False):
        """exato=True: apenas 'Tor:nome' e 'Tor:nome:*' (não pega
        serviços cujo nome só começa igual)."""
        with self._lock:
            try:
                def casa(n):
                    if exato:
                        return (n == prefixo_nome or
                                n.startswith(prefixo_nome + ':'))
                    return n.startswith(prefixo_nome)
                self._remover_lista([
                    r for r in self.regras
                    if (r.get('categoria') == self.CAT_TOR and
                        casa(r.get('nome', '')))
                ])
            except Exception as e:
                logger.error(f"remover_regras_tor: {e}")

    # ══════════════════════════════════════════════════════
    # PAUSAR / REATIVAR
    # ══════════════════════════════════════════════════════

    def pausar_regra(self, rid):
        with self._lock:
            try:
                for r in self.regras:
                    if r.get('id') == rid:
                        if not r.get('editavel', True):
                            return {'sucesso': False,
                                    'erro': 'Regra não editável'}
                        da = r.get('delete_args', '')
                        if da:
                            res   = _exec_ufw(f'--force {da}')
                            saida = (res.get('saida', '') +
                                     res.get('erro', ''))
                            if not (res['sucesso'] or
                                    'Rule deleted' in saida or
                                    'Deleting' in saida):
                                return {'sucesso': False,
                                        'erro': 'Falha ao pausar'}
                        r['pausada']    = True
                        r['pausada_em'] = datetime.now().isoformat()
                        self._salvar()
                        return {'sucesso': True}
                return {'sucesso': False,
                        'erro': 'Regra não encontrada'}
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
                            return {'sucesso': False,
                                    'erro': 'Dados incompletos'}
                        res   = _exec_ufw(args)
                        saida = (res.get('saida', '') +
                                 res.get('erro', ''))
                        if (res['sucesso'] or
                                'Rule added' in saida or
                                'Skipping' in saida):
                            r['pausada'] = False
                            r.pop('pausada_em', None)
                            self._salvar()
                            return {'sucesso': True}
                        return {'sucesso': False,
                                'erro': res.get('erro', 'Erro')}
                return {'sucesso': False, 'erro': 'Não encontrada'}
            except Exception as e:
                logger.error(f"reativar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # EDITAR
    # ══════════════════════════════════════════════════════

    def editar_regra(self, dados):
        with self._lock:
            try:
                rid = dados.get('id', '')
                for i, r in enumerate(self.regras):
                    if r.get('id') == rid:
                        if not r.get('editavel', True):
                            return {'sucesso': False,
                                    'erro': 'Regra não editável'}
                        if not r.get('pausada', False):
                            da = r.get('delete_args', '')
                            if da:
                                _exec_ufw(f'--force {da}')
                        self.regras.pop(i)
                        self._salvar()
                        return self.adicionar_regra(dados)
                return {'sucesso': False, 'erro': 'Não encontrada'}
            except Exception as e:
                logger.error(f"editar_regra: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # INTERFACE DO SISTEMA (timer 5 min)
    # ══════════════════════════════════════════════════════

    def iniciar_mudanca_interface(self, interface):
        try:
            interface = (interface or '').strip()
            if interface and not RE_IFACE.match(interface):
                return {'sucesso': False, 'erro': 'Interface inválida'}
            anterior = self._config.get('interface_sistema', '')
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
            self._timer = threading.Timer(300, self._reverter_interface)
            self._timer.daemon = True
            self._timer.start()

            return {
                'sucesso': True,
                'mensagem': (f'Interface alterada para '
                             f'"{interface or "todas"}". '
                             f'Confirme em 5 minutos!'),
                'tempo': 300
            }
        except Exception as e:
            logger.error(f"iniciar_mudanca_interface: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def confirmar_mudanca_interface(self):
        try:
            if self._config.get('pendente_confirmado', True):
                return {'sucesso': False,
                        'erro': 'Nenhuma mudança pendente'}
            if self._timer:
                self._timer.cancel()
                self._timer = None
            self._config['pendente_confirmado'] = True
            for k in ('interface_anterior', 'interface_pendente',
                      'pendente_iniciado_em'):
                self._config.pop(k, None)
            self._salvar_config()
            return {'sucesso': True, 'mensagem': 'Interface confirmada!'}
        except Exception as e:
            logger.error(f"confirmar_mudanca_interface: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _reverter_interface(self):
        try:
            anterior = self._config.get('interface_anterior', '')
            self._config.update({'interface_sistema': anterior,
                                 'pendente_confirmado': True})
            for k in ('interface_pendente', 'interface_anterior',
                      'pendente_iniciado_em'):
                self._config.pop(k, None)
            self._salvar_config()
            self.garantir_regra_sistema()
            logger.error("Interface revertida (timeout 5 min)")
        except Exception as e:
            logger.error(f"_reverter_interface: {e}")

    def status_mudanca_interface(self):
        try:
            pendente   = self._config.get('interface_pendente')
            iniciado   = self._config.get('pendente_iniciado_em')
            confirmado = self._config.get('pendente_confirmado', True)

            if confirmado or not pendente:
                return {'pendente': False,
                        'interface_atual': self._config.get(
                            'interface_sistema', '')}

            restante = 0
            if iniciado:
                dt = datetime.fromisoformat(iniciado)
                restante = max(0, 300 - int(
                    (datetime.now() - dt).total_seconds()))

            return {
                'pendente':           True,
                'interface_pendente': pendente,
                'interface_anterior': self._config.get(
                    'interface_anterior', ''),
                'restante':           restante,
                'interface_atual':    self._config.get(
                    'interface_sistema', '')
            }
        except Exception as e:
            logger.error(f"status_mudanca_interface: {e}")
            return {'pendente': False}

    # ══════════════════════════════════════════════════════
    # HELPER PARA OUTROS MÓDULOS (Tor, Tox, DNS)
    # ══════════════════════════════════════════════════════

    def adicionar_regra_automatica(self, chave_nome, dados, categoria):
        nome_busca = dados.get('nome', chave_nome)
        for r in self.regras:
            if (r.get('nome') == nome_busca and
                    r.get('categoria') == categoria):
                return {'sucesso': True,
                        'aviso': f'Regra "{nome_busca}" já existe'}
        d = dict(dados)
        d.setdefault('nome', chave_nome)
        return self.adicionar_regra(d, categoria=categoria,
                                    editavel=False)

    # ══════════════════════════════════════════════════════
    # DIAGNÓSTICO
    # ══════════════════════════════════════════════════════

    def _faltando(self, categoria, obrigatorias):
        nomes = {r.get('nome', '') for r in self.regras
                 if r.get('categoria') == categoria}
        return [{'nome': n, 'desc': d, 'tipo': 'ausente'}
                for n, d in obrigatorias if n not in nomes]

    def diagnosticar_regras_tor(self):
        return self._faltando(self.CAT_TOR, [
            ('Tor:infra:saida:livre', 'Saída TCP livre na WAN'),
            ('Tor:infra:saida:53',    'Saída UDP 53 (DNS)'),
            ('Tor:infra:lo:in:9050',  'Loopback in 9050 (SOCKS)'),
            ('Tor:infra:lo:out:9050', 'Loopback out 9050'),
        ])

    def diagnosticar_regras_tox(self):
        return self._faltando(self.CAT_TOX, [
            ('Tox:infra:saida:udp',     'Saída UDP (DHT / hole punching)'),
            ('Tox:infra:saida:tcp:443', 'Saída TCP 443 (relay)'),
            ('Tox:infra:entrada:udp',   'Entrada UDP 33445-33545'),
        ])
