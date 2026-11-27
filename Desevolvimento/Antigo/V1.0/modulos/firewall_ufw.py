#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Firewall UFW - RRFS Servidores
Adaptado e integrado ao sistema RRFS
"""

import os
import re
import json
import time
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
    encontrado = shutil.which('ufw')
    return encontrado or None


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
                'PATH': '/usr/local/sbin:/usr/local/bin:'
                        '/usr/sbin:/usr/bin:/sbin:/bin',
                'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'
            }
        )
        return {
            'sucesso': r.returncode == 0,
            'saida': r.stdout.strip(),
            'erro': r.stderr.strip(),
            'codigo': r.returncode
        }
    except subprocess.TimeoutExpired:
        logger.error(f"UFW timeout: {args}")
        return {'sucesso': False, 'saida': '',
                'erro': 'Timeout', 'codigo': -1}
    except Exception as e:
        logger.error(f"_exec_ufw: {e}")
        return {'sucesso': False, 'saida': '',
                'erro': str(e), 'codigo': -1}


class FirewallUFW:

    # ── categorias de regra ───────────────────────────────
    CAT_USUARIO  = 'usuario'   # editável pelo admin
    CAT_SISTEMA  = 'sistema'   # porta 2000, não editável
    CAT_TOR      = 'tor'       # criada pelo Tor, não editável
    CAT_VPN      = 'vpn'       # criada pela VPN, não editável

    def __init__(self, base_dir):
        self.base_dir   = base_dir
        self._path      = os.path.join(
            base_dir, 'dados', 'regras_ufw.json'
        )
        self._cfg_path  = os.path.join(
            base_dir, 'dados', 'config_ufw.json'
        )
        self.regras     = []
        self._config    = {}
        self._pendente  = None   # mudança de interface pendente
        self._timer     = None
        self._carregar()
        self._carregar_config()

    # ── persistência ──────────────────────────────────────

    def _carregar(self):
        try:
            if os.path.exists(self._path):
                with open(self._path, 'r') as f:
                    self.regras = json.load(f)
        except Exception as e:
            logger.error(f"carregar regras: {e}")
            self.regras = []

    def _salvar(self):
        try:
            os.makedirs(os.path.dirname(self._path), exist_ok=True)
            with open(self._path, 'w') as f:
                json.dump(self.regras, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"salvar regras: {e}")

    def _carregar_config(self):
        try:
            if os.path.exists(self._cfg_path):
                with open(self._cfg_path, 'r') as f:
                    self._config = json.load(f)
        except Exception as e:
            logger.error(f"carregar config ufw: {e}")
            self._config = {}

    def _salvar_config(self):
        try:
            os.makedirs(os.path.dirname(self._cfg_path), exist_ok=True)
            with open(self._cfg_path, 'w') as f:
                json.dump(self._config, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"salvar config ufw: {e}")

    # ── inicialização ─────────────────────────────────────

    def inicializar(self):
        """Inicializa UFW com política deny all"""
        try:
            _exec_ufw('default deny incoming')
            _exec_ufw('default deny outgoing')
            _exec_ufw('--force enable')

            # reaplicar regras ativas
            ativas = [r for r in self.regras
                      if not r.get('pausada') and
                      r.get('categoria') != self.CAT_SISTEMA]
            for r in ativas:
                args = r.get('ufw_args', '')
                if args:
                    _exec_ufw(args)
        except Exception as e:
            logger.error(f"inicializar ufw: {e}")

    def garantir_regra_sistema(self):
        """Garante regra da porta 2000 sempre ativa"""
        try:
            # Remover antigas do sistema
            self.regras = [
                r for r in self.regras
                if r.get('categoria') != self.CAT_SISTEMA
            ]

            interface = self._config.get('interface_sistema', '')
            args      = self._montar_args_porta_sistema(interface)

            _exec_ufw(args)

            regra = {
                'id': 'sistema_porta_2000',
                'nome': 'RRFS Sistema (porta 2000)',
                'categoria': self.CAT_SISTEMA,
                'interface': interface,
                'direcao': 'in',
                'protocolo': 'tcp',
                'ip': '',
                'porta': str(PORTA_SISTEMA),
                'ufw_args': args,
                'delete_args': f'delete {args}',
                'pausada': False,
                'editavel': False,
                'timestamp': datetime.now().isoformat()
            }
            self.regras.insert(0, regra)
            self._salvar()
        except Exception as e:
            logger.error(f"garantir_regra_sistema: {e}")

    def _montar_args_porta_sistema(self, interface=''):
        if interface:
            return (f'allow in on {interface} '
                    f'to any port {PORTA_SISTEMA} proto tcp')
        return f'allow in to any port {PORTA_SISTEMA} proto tcp'

    # ── status ────────────────────────────────────────────

    def obter_status(self):
        try:
            r = _exec_ufw('status verbose')
            txt = r.get('saida', '')
            return {
                'ativo': 'active' in txt.lower()
                         .split('\n')[0] if txt else False,
                'politica_entrada': self._pol(txt, 'incoming'),
                'politica_saida':   self._pol(txt, 'outgoing'),
                'texto': txt
            }
        except Exception as e:
            logger.error(f"obter_status ufw: {e}")
            return {'ativo': False, 'politica_entrada': 'unknown',
                    'politica_saida': 'unknown', 'texto': ''}

    def _pol(self, txt, termo):
        t = txt.lower()
        if f'deny ({termo})' in t:   return 'deny'
        if f'allow ({termo})' in t:  return 'allow'
        return 'unknown'

    # ── listar ────────────────────────────────────────────

    def listar_regras_salvas(self):
        return self.regras

    # ── validações ────────────────────────────────────────

    def _validar_porta(self, porta):
        porta = porta.strip()
        if ':' in porta:
            p = porta.split(':')
            if len(p) != 2:
                return False, 'Range inválido. Ex: 8000:9000'
            for x in p:
                if not x.strip().isdigit() or \
                   not (1 <= int(x.strip()) <= 65535):
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
                return False, f'Octeto > 255'
        if '/' in ip and int(ip.split('/')[1]) > 32:
            return False, 'Máscara > /32'
        return True, ''

    # ── montar args ───────────────────────────────────────

    def _montar_args(self, direcao, interface, protocolo, ip, porta):
        """Monta argumentos UFW para todos os casos"""
        partes    = ['allow']
        tem_ip    = bool(ip)
        tem_porta = bool(porta)
        tem_iface = bool(interface)

        def _proto_str():
            # ambos = sem restrição de protocolo
            if protocolo in ('ambos', 'both', ''):
                return ''
            return protocolo

        p = _proto_str()

        # ── só porta ──────────────────────────────────────
        if tem_porta and not tem_ip:
            if not tem_iface:
                if p:
                    partes += [direcao, f'{porta}/{p}']
                else:
                    partes += [direcao, str(porta)]
            else:
                partes.append(direcao)
                partes.append(f'on {interface}')
                if direcao == 'in':
                    dest = f'to any port {porta}'
                    if p: dest += f' proto {p}'
                    partes.append(dest)
                else:
                    dest = f'from any to any port {porta}'
                    if p: dest += f' proto {p}'
                    partes.append(dest)

        # ── só IP ─────────────────────────────────────────
        elif tem_ip and not tem_porta:
            if direcao == 'in':
                partes.append('in')
                if tem_iface:
                    partes.append(f'on {interface}')
                partes.append(f'from {ip}')
            else:
                partes.append('out')
                if tem_iface:
                    partes.append(f'on {interface}')
                partes.append(f'to {ip}')

        # ── IP + porta ────────────────────────────────────
        elif tem_ip and tem_porta:
            if direcao == 'in':
                partes.append('in')
                if tem_iface:
                    partes.append(f'on {interface}')
                dest = f'from {ip} to any port {porta}'
                if p: dest += f' proto {p}'
                partes.append(dest)
            else:
                partes.append('out')
                if tem_iface:
                    partes.append(f'on {interface}')
                dest = f'to {ip} port {porta}'
                if p: dest += f' proto {p}'
                partes.append(dest)

        return ' '.join(partes)

    def _montar_regras_direcao(self, direcao, interface,
                                protocolo, ip, porta):
        """
        Expande 'ambos' em duas chamadas (in + out).
        Retorna lista de args strings.
        """
        if direcao == 'ambos':
            return [
                self._montar_args(
                    'in', interface, protocolo, ip, porta
                ),
                self._montar_args(
                    'out', interface, protocolo, ip, porta
                )
            ]
        return [self._montar_args(
            direcao, interface, protocolo, ip, porta
        )]

    # ── adicionar ─────────────────────────────────────────

    def adicionar_regra(self, dados,
                        categoria=None, editavel=True):
        try:
            nome      = dados.get('nome', '').strip()
            interface = dados.get('interface', '').strip()
            direcao   = dados.get('direcao', 'in').strip()
            protocolo = dados.get('protocolo', 'tcp').strip()
            ip        = dados.get('ip', '').strip()
            porta     = dados.get('porta', '').strip()
            cat       = categoria or self.CAT_USUARIO

            if not porta and not ip:
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

            lista_args = self._montar_regras_direcao(
                direcao, interface, protocolo, ip, porta
            )

            ids_criados = []
            for args in lista_args:
                r = _exec_ufw(args)
                saida = (r.get('saida', '') +
                         r.get('erro', ''))
                ok = (r['sucesso'] or
                      'Rule added' in saida or
                      'Rules updated' in saida or
                      'Skipping' in saida)
                if not ok:
                    logger.error(
                        f"UFW falhou: {args} → {saida}"
                    )
                    continue

                dir_real = ('in' if direcao == 'ambos'
                            and args == lista_args[0]
                            else
                            'out' if direcao == 'ambos'
                            else direcao)

                import uuid
                rid = str(uuid.uuid4())[:8]
                regra = {
                    'id': rid,
                    'nome': nome,
                    'categoria': cat,
                    'interface': interface,
                    'direcao': dir_real,
                    'protocolo': protocolo,
                    'ip': ip,
                    'porta': porta,
                    'ufw_args': args,
                    'delete_args': f'delete {args}',
                    'pausada': False,
                    'editavel': editavel,
                    'timestamp': datetime.now().isoformat()
                }
                self.regras.append(regra)
                ids_criados.append(rid)

            if ids_criados:
                self._salvar()
                return {'sucesso': True,
                        'ids': ids_criados}
            return {'sucesso': False,
                    'erro': 'Falha ao aplicar regra no UFW'}

        except Exception as e:
            logger.error(f"adicionar_regra: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── remover ───────────────────────────────────────────

    def remover_regra(self, rid):
        try:
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
                    return {'sucesso': True}
            return {'sucesso': False, 'erro': 'Regra não encontrada'}
        except Exception as e:
            logger.error(f"remover_regra: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_regras_por_categoria(self, categoria):
        """Remove todas as regras de uma categoria"""
        try:
            para_remover = [
                r for r in self.regras
                if r.get('categoria') == categoria
            ]
            for r in para_remover:
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
            logger.error(f"remover_regras_por_categoria: {e}")

    # ── pausar / reativar ─────────────────────────────────

    def pausar_regra(self, rid):
        try:
            for r in self.regras:
                if r.get('id') == rid:
                    if not r.get('editavel', True):
                        return {'sucesso': False,
                                'erro': 'Regra não editável'}
                    da = r.get('delete_args', '')
                    if da:
                        res = _exec_ufw(f'--force {da}')
                        saida = (res.get('saida', '') +
                                 res.get('erro', ''))
                        if not (res['sucesso'] or
                                'Rule deleted' in saida or
                                'Deleting' in saida):
                            return {'sucesso': False,
                                    'erro': 'Falha ao pausar'}
                    r['pausada']   = True
                    r['pausada_em'] = datetime.now().isoformat()
                    self._salvar()
                    return {'sucesso': True}
            return {'sucesso': False, 'erro': 'Regra não encontrada'}
        except Exception as e:
            logger.error(f"pausar_regra: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def reativar_regra(self, rid):
        try:
            for r in self.regras:
                if r.get('id') == rid:
                    args = r.get('ufw_args', '')
                    if not args:
                        return {'sucesso': False,
                                'erro': 'Dados incompletos'}
                    res  = _exec_ufw(args)
                    saida = (res.get('saida', '') +
                             res.get('erro', ''))
                    ok = (res['sucesso'] or
                          'Rule added' in saida or
                          'Skipping' in saida)
                    if ok:
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

    # ── editar ────────────────────────────────────────────

    def editar_regra(self, dados):
        try:
            rid = dados.get('id', '')
            for i, r in enumerate(self.regras):
                if r.get('id') == rid:
                    if not r.get('editavel', True):
                        return {'sucesso': False,
                                'erro': 'Regra não editável'}
                    # remove antiga
                    if not r.get('pausada', False):
                        da = r.get('delete_args', '')
                        if da:
                            _exec_ufw(f'--force {da}')
                    self.regras.pop(i)
                    self._salvar()
                    # adiciona nova
                    return self.adicionar_regra(dados)
            return {'sucesso': False, 'erro': 'Não encontrada'}
        except Exception as e:
            logger.error(f"editar_regra: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── interface do sistema (timer 5 min) ────────────────

    def iniciar_mudanca_interface(self, interface):
        """
        Aplica nova interface para o sistema com timer.
        Se admin não confirmar em 5 min, reverte.
        """
        try:
            interface_anterior = self._config.get(
                'interface_sistema', ''
            )

            # aplicar imediatamente
            self._config['interface_sistema']          = interface
            self._config['interface_pendente']         = interface
            self._config['interface_anterior']         = interface_anterior
            self._config['pendente_iniciado_em']       = datetime.now().isoformat()
            self._config['pendente_confirmado']        = False
            self._salvar_config()
            self.garantir_regra_sistema()

            # timer de 5 minutos
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
            if not self._config.get('pendente_confirmado') is False:
                return {'sucesso': False,
                        'erro': 'Nenhuma mudança pendente'}
            if self._timer:
                self._timer.cancel()
                self._timer = None
            self._config['pendente_confirmado'] = True
            self._config.pop('interface_anterior', None)
            self._config.pop('interface_pendente', None)
            self._config.pop('pendente_iniciado_em', None)
            self._salvar_config()
            return {'sucesso': True,
                    'mensagem': 'Interface confirmada!'}
        except Exception as e:
            logger.error(f"confirmar_mudanca_interface: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _reverter_interface(self):
        try:
            anterior = self._config.get('interface_anterior', '')
            self._config['interface_sistema']  = anterior
            self._config['pendente_confirmado'] = True
            self._config.pop('interface_pendente', None)
            self._config.pop('interface_anterior', None)
            self._config.pop('pendente_iniciado_em', None)
            self._salvar_config()
            self.garantir_regra_sistema()
            logger.error(
                "Interface revertida automaticamente "
                "(timeout 5 min)"
            )
        except Exception as e:
            logger.error(f"_reverter_interface: {e}")

    def status_mudanca_interface(self):
        try:
            pendente = self._config.get('interface_pendente')
            iniciado = self._config.get('pendente_iniciado_em')
            confirmado = self._config.get('pendente_confirmado', True)

            if confirmado or not pendente:
                return {
                    'pendente': False,
                    'interface_atual': self._config.get(
                        'interface_sistema', ''
                    )
                }

            restante = 0
            if iniciado:
                from datetime import datetime
                dt = datetime.fromisoformat(iniciado)
                elapsed = (datetime.now() - dt).total_seconds()
                restante = max(0, 300 - int(elapsed))

            return {
                'pendente': True,
                'interface_pendente': pendente,
                'interface_anterior': self._config.get(
                    'interface_anterior', ''
                ),
                'restante': restante,
                'interface_atual': self._config.get(
                    'interface_sistema', ''
                )
            }
        except Exception as e:
            logger.error(f"status_mudanca_interface: {e}")
            return {'pendente': False}

    # ── helpers públicos para outros módulos ─────────────

    def adicionar_regra_automatica(self, nome, dados,
                                    categoria):
        """
        Adiciona regra automática (Tor, VPN) — não editável
        pelo admin.
        """
        return self.adicionar_regra(
            dados, categoria=categoria, editavel=False
        )

    def remover_regras_tor(self, prefixo_nome):
        """Remove regras do Tor pelo prefixo do nome"""
        try:
            para_remover = [
                r for r in self.regras
                if (r.get('categoria') == self.CAT_TOR and
                    r.get('nome', '').startswith(prefixo_nome))
            ]
            for r in para_remover:
                if not r.get('pausada', False):
                    da = r.get('delete_args', '')
                    if da:
                        _exec_ufw(f'--force {da}')
            self.regras = [
                r for r in self.regras
                if r not in para_remover
            ]
            self._salvar()
        except Exception as e:
            logger.error(f"remover_regras_tor: {e}")

    def remover_regras_vpn(self, prefixo_nome):
        """Remove regras da VPN pelo prefixo do nome"""
        try:
            para_remover = [
                r for r in self.regras
                if (r.get('categoria') == self.CAT_VPN and
                    r.get('nome', '').startswith(prefixo_nome))
            ]
            for r in para_remover:
                if not r.get('pausada', False):
                    da = r.get('delete_args', '')
                    if da:
                        _exec_ufw(f'--force {da}')
            self.regras = [
                r for r in self.regras
                if r not in para_remover
            ]
            self._salvar()
        except Exception as e:
            logger.error(f"remover_regras_vpn: {e}")
