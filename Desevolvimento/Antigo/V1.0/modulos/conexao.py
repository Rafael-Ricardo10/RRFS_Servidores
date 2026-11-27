#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Módulo de Conexão - RRFS Servidores
Gerencia WAN, VPN de saída e VPN de acesso ao servidor.
Tor como rede principal REMOVIDO.
"""

import os
import re
import json
import time
import shutil
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from threading import Lock

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Conexao')

PORTA_SISTEMA = 2000
lock = Lock()


def _cmd(comando, timeout=60):
    return executar_comando(comando, timeout=timeout)


def _salvar(path, dados):
    try:
        os.makedirs(os.path.dirname(str(path)), exist_ok=True)
        with open(str(path), 'w', encoding='utf-8') as f:
            json.dump(dados, f, indent=2, ensure_ascii=False)
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


class ConexaoManager:

    def __init__(self, base_dir):
        self.base_dir  = Path(base_dir)
        self.dados_dir = self.base_dir / 'dados' / 'conexao'
        self.vpn_dir   = self.dados_dir / 'vpns'
        self.ovpn_dir  = self.dados_dir / 'ovpn_acesso'

        for d in [self.dados_dir, self.vpn_dir, self.ovpn_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self._cfg_path  = self.dados_dir / 'config.json'
        self._vpns_path = self.dados_dir / 'vpns.json'
        self._wifi_path = self.dados_dir / 'wifis.json'
        self._acc_path  = self.dados_dir / 'vpn_acesso.json'
        self._firewall  = None

    def set_firewall(self, fw):
        self._firewall = fw

    # ── status geral ──────────────────────────────────────

    def obter_status(self):
        try:
            cfg     = _carregar(self._cfg_path, {})
            vpns    = _carregar(self._vpns_path, [])
            acesso  = _carregar(self._acc_path, {})

            vpn_ativa = next(
                (v for v in vpns if v.get('ativa')), None
            )

            tor_r  = _cmd('systemctl is-active tor 2>/dev/null')
            tor_on = tor_r['sucesso'] and 'active' in tor_r.get(
                'saida', ''
            )

            tun_ip = ''
            r_tun  = _cmd('ip -4 addr show tun0 2>/dev/null')
            if r_tun['sucesso']:
                m = re.search(
                    r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                    r_tun['saida']
                )
                if m:
                    tun_ip = m.group(1)

            return {
                'modo': cfg.get('modo', 'direto'),
                'modo_nome': cfg.get('modo_nome', 'Direto'),
                'wan_interface': cfg.get('wan', {}).get(
                    'interface', 'N/A'
                ),
                'wan_tipo': cfg.get('wan', {}).get('tipo', ''),
                'ssid_ativo': cfg.get('wan', {}).get(
                    'ssid_ativo', ''
                ),
                'vpn_ativa': vpn_ativa,
                'vpn_tun_ip': tun_ip,
                'tor_ativo': tor_on,
                'vpn_acesso_ativa': acesso.get('ativa', False),
                'vpn_acesso_modo': acesso.get('modo', ''),
                'total_vpns': len(vpns)
            }
        except Exception as e:
            logger.error(f"obter_status conexao: {e}")
            return {}

    # ── interfaces ────────────────────────────────────────

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
                skip = ['lo', 'docker', 'br-', 'veth',
                        'virbr', 'tun', 'tap', 'wg']
                if any(nome.startswith(p) for p in skip):
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
                ip_r = _cmd(f'ip -4 addr show {nome}')
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
                    'nome': nome, 'tipo': tipo,
                    'mac': mac, 'ip': ip_addr,
                    'estado': estado
                })
        except Exception as e:
            logger.error(f"listar_interfaces: {e}")
        return interfaces

    # ── WiFi ──────────────────────────────────────────────

    def escanear_wifi(self, interface):
        try:
            r = _cmd(
                f'nmcli -t -f SSID,SIGNAL,SECURITY '
                f'dev wifi list ifname {interface} '
                f'--rescan yes',
                timeout=30
            )
            redes = []
            if r['sucesso']:
                for linha in r['saida'].splitlines():
                    p = linha.split(':')
                    if len(p) >= 2 and p[0]:
                        redes.append({
                            'ssid': p[0],
                            'sinal': p[1] if len(p) > 1 else '0',
                            'seguranca': p[2] if len(p) > 2
                            else 'Aberta'
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
        with lock:
            try:
                interface = dados.get('interface', '')
                ssid      = dados.get('ssid', '')
                senha     = dados.get('senha', '')

                if not interface or not ssid:
                    return {'sucesso': False,
                            'erro': 'Interface e SSID obrigatórios'}

                conn = f"rrfs-wifi-{ssid.replace(' ', '_')}"
                _cmd(f'nmcli con delete "{conn}"', timeout=10)

                if senha:
                    r = _cmd(
                        f'nmcli dev wifi connect "{ssid}" '
                        f'password "{senha}" ifname {interface} '
                        f'name "{conn}"',
                        timeout=60
                    )
                else:
                    r = _cmd(
                        f'nmcli dev wifi connect "{ssid}" '
                        f'ifname {interface} name "{conn}"',
                        timeout=60
                    )

                if not r['sucesso']:
                    return {'sucesso': False,
                            'erro': r.get('erro', 'Falha')}

                cfg = _carregar(self._cfg_path, {})
                cfg['wan'] = {
                    'interface': interface, 'tipo': 'wifi',
                    'ssid_ativo': ssid,
                    'configurado_em': _agora()
                }
                _salvar(self._cfg_path, cfg)
                return {'sucesso': True,
                        'mensagem': f'Conectado: {ssid}'}
            except Exception as e:
                logger.error(f"conectar_wifi: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ── WAN ───────────────────────────────────────────────

    def configurar_wan(self, dados):
        with lock:
            try:
                interface = dados.get('interface', '')
                tipo      = dados.get('tipo', 'ethernet')
                modo      = dados.get('modo', 'dhcp')

                if not interface:
                    return {'sucesso': False,
                            'erro': 'Interface obrigatória'}

                if tipo == 'ethernet':
                    if modo == 'dhcp':
                        conn = f'rrfs-wan-{interface}'
                        _cmd(f'nmcli con delete "{conn}"',
                             timeout=10)
                        _cmd(
                            f'nmcli con add con-name "{conn}" '
                            f'type ethernet ifname {interface} '
                            f'ipv4.method auto',
                            timeout=30
                        )
                        _cmd(f'nmcli con up "{conn}"', timeout=30)
                    elif modo == 'fixo':
                        ip   = dados.get('ip', '')
                        mask = dados.get('mascara', '24')
                        gw   = dados.get('gateway', '')
                        dns  = dados.get('dns', '8.8.8.8')
                        if not ip:
                            return {'sucesso': False,
                                    'erro': 'IP obrigatório'}
                        conn = f'rrfs-wan-{interface}'
                        _cmd(f'nmcli con delete "{conn}"',
                             timeout=10)
                        cmd = (
                            f'nmcli con add con-name "{conn}" '
                            f'type ethernet ifname {interface} '
                            f'ipv4.method manual '
                            f'ipv4.addresses {ip}/{mask}'
                        )
                        if gw:
                            cmd += f' ipv4.gateway {gw}'
                        if dns:
                            cmd += f' ipv4.dns {dns}'
                        _cmd(cmd, timeout=30)
                        _cmd(f'nmcli con up "{conn}"', timeout=30)

                cfg = _carregar(self._cfg_path, {})
                cfg['wan'] = {
                    'interface': interface, 'tipo': tipo,
                    'modo': modo,
                    'configurado_em': _agora()
                }
                _salvar(self._cfg_path, cfg)
                return {'sucesso': True,
                        'mensagem': f'WAN configurada: {interface}'}
            except Exception as e:
                logger.error(f"configurar_wan: {e}")
                return {'sucesso': False, 'erro': str(e)}

    # ── VPNs de saída ─────────────────────────────────────

    def importar_vpn_saida(self, nome, conteudo,
                            usuario='', senha=''):
        try:
            vid    = _gerar_id()
            arq    = self.vpn_dir / f'{vid}.ovpn'
            arq_au = ''

            # extrair ip/porta
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

            # credenciais
            if usuario and senha:
                arq_au = str(self.vpn_dir / f'{vid}_auth.txt')
                Path(arq_au).write_text(
                    f'{usuario}\n{senha}\n'
                )
                os.chmod(arq_au, 0o600)

            # limpar ovpn
            conteudo_limpo = self._limpar_ovpn(
                conteudo, arq_au
            )
            arq.write_text(conteudo_limpo, encoding='utf-8')
            os.chmod(str(arq), 0o600)

            # resolver hostname
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
                'id': vid, 'nome': nome,
                'arquivo': str(arq),
                'arquivo_auth': arq_au,
                'ip_servidor': ip_srv, 'porta': porta,
                'protocolo': proto,
                'usuario': usuario,
                'portas_saida': ['80', '443'],
                'ativa': False,
                'importado_em': _agora()
            }
            vpns.append(info)
            _salvar(self._vpns_path, vpns)

            # regra UFW de saída
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
            if l.startswith('auth-user-pass'):
                continue
            if l.startswith('up ') or l.startswith('down '):
                continue
            if l.startswith('script-security'):
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
                    for a in [v.get('arquivo', ''),
                               v.get('arquivo_auth', '')]:
                        if a:
                            try:
                                Path(a).unlink(missing_ok=True)
                            except Exception as e:
                                logger.error(
                                    f"remover arq vpn: {e}"
                                )
                    nome = v['nome']
                    vpns.pop(i)
                    _salvar(self._vpns_path, vpns)
                    return {'sucesso': True,
                            'mensagem': f'VPN "{nome}" removida'}
            return {'sucesso': False, 'erro': 'Não encontrada'}
        except Exception as e:
            logger.error(f"remover_vpn_saida: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def configurar_portas_saida_vpn(self, vid, portas):
        """Define quais portas são liberadas pelo túnel VPN"""
        try:
            vpns = _carregar(self._vpns_path, [])
            for v in vpns:
                if v['id'] == vid:
                    v['portas_saida'] = portas
                    _salvar(self._vpns_path, vpns)
                    # reaplicar regras UFW
                    self._remover_regra_vpn_saida(v)
                    self._criar_regra_vpn_saida(v)
                    return {'sucesso': True,
                            'mensagem': 'Portas atualizadas'}
            return {'sucesso': False, 'erro': 'VPN não encontrada'}
        except Exception as e:
            logger.error(f"configurar_portas_saida_vpn: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── conectar VPN ──────────────────────────────────────

    def conectar_vpn(self, vid):
        with lock:
            try:
                vpns = _carregar(self._vpns_path, [])
                vpn  = next(
                    (v for v in vpns if v['id'] == vid), None
                )
                if not vpn:
                    return {'sucesso': False,
                            'erro': 'VPN não encontrada'}

                # desconectar atual
                self._desconectar_vpn_interno()
                time.sleep(2)

                arq = vpn.get('arquivo', '')
                if not arq or not Path(arq).exists():
                    return {'sucesso': False,
                            'erro': 'Arquivo VPN não encontrado'}

                # reprocessar ovpn
                conteudo = Path(arq).read_text(encoding='utf-8')
                limpo = self._limpar_ovpn(
                    conteudo, vpn.get('arquivo_auth', '')
                )
                Path(arq).write_text(limpo, encoding='utf-8')
                os.chmod(arq, 0o600)

                # verificar openvpn
                r = _cmd('which openvpn', timeout=5)
                if not r['sucesso']:
                    _cmd(
                        'apt-get install -y openvpn',
                        timeout=180
                    )

                log_f = str(self.dados_dir / 'openvpn.log')
                pid_f = str(self.dados_dir / 'openvpn.pid')
                Path(log_f).write_text('')

                _cmd('killall -9 openvpn', timeout=5)
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

                env = os.environ.copy()
                env['PATH'] = (
                    '/usr/local/sbin:/usr/local/bin:'
                    '/usr/sbin:/usr/bin:/sbin:/bin'
                )
                proc = subprocess.Popen(
                    cmd, shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    start_new_session=True
                )
                time.sleep(4)

                # aguardar tun0
                tunnel = False
                for i in range(30):
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
                    return {
                        'sucesso': False,
                        'erro': f'VPN não conectou: '
                               f'{log_txt[-300:]}'
                    }

                # IP do túnel
                tun_ip = ''
                r = _cmd('ip -4 addr show tun0', timeout=5)
                if r['sucesso']:
                    m = re.search(
                        r'inet\s+(\d+\.\d+\.\d+\.\d+)',
                        r['saida']
                    )
                    if m:
                        tun_ip = m.group(1)

                # marcar ativa
                for v in vpns:
                    v['ativa'] = (v['id'] == vid)
                _salvar(self._vpns_path, vpns)

                # iptables kill switch
                cfg = _carregar(self._cfg_path, {})
                wan = cfg.get('wan', {}).get('interface', '')
                if wan:
                    self._aplicar_kill_switch(wan, vpn)

                return {
                    'sucesso': True,
                    'mensagem': (
                        f'VPN "{vpn["nome"]}" conectada. '
                        f'IP: {tun_ip}'
                    ),
                    'tun_ip': tun_ip
                }
            except Exception as e:
                logger.error(f"conectar_vpn: {e}")
                return {'sucesso': False, 'erro': str(e)}

    def desconectar_vpn(self, vid=None):
        self._desconectar_vpn_interno()
        return {'sucesso': True, 'mensagem': 'VPN desconectada'}

    def _desconectar_vpn_interno(self):
        try:
            pid_f = self.dados_dir / 'openvpn.pid'
            if pid_f.exists():
                pid = pid_f.read_text().strip()
                if pid:
                    _cmd(f'kill {pid}', timeout=5)
                    time.sleep(2)
                    _cmd(f'kill -9 {pid}', timeout=5)
                pid_f.unlink(missing_ok=True)
            _cmd('killall openvpn', timeout=5)
            time.sleep(1)
            _cmd('killall -9 openvpn', timeout=5)
            vpns = _carregar(self._vpns_path, [])
            for v in vpns:
                v['ativa'] = False
            _salvar(self._vpns_path, vpns)
        except Exception as e:
            logger.error(f"desconectar_vpn_interno: {e}")

    # ── iptables kill switch ───────────────────────────────

    def _aplicar_kill_switch(self, wan, vpn):
        try:
            ip   = vpn.get('ip_servidor', '')
            port = vpn.get('porta', '')
            proto = vpn.get('protocolo', 'udp')

            cmds = [
                'iptables -F',
                'iptables -X',
                'iptables -t nat -F',
                f'iptables -A INPUT -i lo -j ACCEPT',
                f'iptables -A OUTPUT -o lo -j ACCEPT',
                f'iptables -A INPUT -p tcp '
                f'--dport {PORTA_SISTEMA} -j ACCEPT',
                f'iptables -A OUTPUT -o {wan} '
                f'-d {ip} -p {proto} --dport {port} -j ACCEPT',
                f'iptables -A INPUT -i {wan} '
                f'-s {ip} -p {proto} --sport {port} -j ACCEPT',
                f'iptables -A OUTPUT -o {wan} '
                f'-p udp --dport 67:68 -j ACCEPT',
                f'iptables -A OUTPUT -o tun0 -j ACCEPT',
                f'iptables -A INPUT -i tun0 -m state '
                f'--state ESTABLISHED,RELATED -j ACCEPT',
                f'iptables -A INPUT -i {wan} -m state '
                f'--state ESTABLISHED,RELATED -j ACCEPT',
                f'iptables -A OUTPUT -o {wan} -j DROP',
            ]
            for c in cmds:
                _cmd(c, timeout=10)
        except Exception as e:
            logger.error(f"kill_switch: {e}")

    # ── modo de conexão ───────────────────────────────────

    def aplicar_modo(self, modo, vpn_id=None):
        try:
            cfg = _carregar(self._cfg_path, {})
            wan = cfg.get('wan', {}).get('interface', '')

            if not wan:
                return {'sucesso': False,
                        'erro': 'Configure a WAN primeiro'}

            self._desconectar_vpn_interno()

            # limpar iptables
            for c in [
                'iptables -F', 'iptables -X',
                'iptables -t nat -F',
                'iptables -P INPUT ACCEPT',
                'iptables -P OUTPUT ACCEPT',
                'iptables -P FORWARD ACCEPT',
            ]:
                _cmd(c, timeout=10)

            if modo == 'direto':
                cfg['modo']      = 'direto'
                cfg['modo_nome'] = 'Direto'
                _salvar(self._cfg_path, cfg)
                return {'sucesso': True,
                        'mensagem': 'Modo direto ativado'}

            elif modo in ('vpn', 'vpn_auto'):
                if modo == 'vpn_auto' or not vpn_id:
                    vpn = self._melhor_vpn()
                    if not vpn:
                        return {'sucesso': False,
                                'erro': 'Nenhuma VPN disponível'}
                    vpn_id = vpn['id']
                r = self.conectar_vpn(vpn_id)
                if r['sucesso']:
                    cfg['modo']      = 'vpn'
                    cfg['modo_nome'] = 'VPN'
                    _salvar(self._cfg_path, cfg)
                return r

            return {'sucesso': False,
                    'erro': f'Modo inválido: {modo}'}
        except Exception as e:
            logger.error(f"aplicar_modo: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _melhor_vpn(self):
        vpns = _carregar(self._vpns_path, [])
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
                    r'avg.*?=\s*[\d.]+/([\d.]+)', r['saida']
                )
                if m:
                    lat = float(m.group(1))
            if lat < menor:
                menor  = lat
                melhor = v
        return melhor

    # ── UFW para VPN saída ────────────────────────────────

    def _criar_regra_vpn_saida(self, vpn):
        if not self._firewall:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            nome_pfx = f'VPN:{vpn["nome"]}'

            # regra para chegar ao servidor VPN
            cfg = _carregar(self._cfg_path, {})
            wan = cfg.get('wan', {}).get('interface', '')
            ip  = vpn.get('ip_servidor', '')
            pt  = vpn.get('porta', '')
            pr  = vpn.get('protocolo', 'udp')

            if ip and pt and wan:
                self._firewall.adicionar_regra_automatica(
                    f'{nome_pfx}:servidor',
                    {
                        'nome': f'{nome_pfx}:servidor',
                        'interface': wan,
                        'direcao': 'out',
                        'protocolo': pr,
                        'ip': ip,
                        'porta': pt
                    },
                    FirewallUFW.CAT_VPN
                )

            # portas de saída pelo túnel
            for porta in vpn.get('portas_saida', ['80', '443']):
                for proto in ['tcp', 'udp']:
                    self._firewall.adicionar_regra_automatica(
                        f'{nome_pfx}:saida:{porta}:{proto}',
                        {
                            'nome': f'{nome_pfx}:saida',
                            'interface': 'tun0',
                            'direcao': 'out',
                            'protocolo': proto,
                            'ip': '',
                            'porta': porta
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

    # ── VPN de acesso ao servidor ─────────────────────────

    def configurar_vpn_acesso(self, dados):
        """
        Configura VPN para o admin acessar o servidor.
        modo: 'ip_publico' ou 'tor'
        portas: lista de portas adicionais além da 2000
        """
        try:
            modo   = dados.get('modo', 'ip_publico')
            portas = dados.get('portas', [])
            if str(PORTA_SISTEMA) not in [str(p) for p in portas]:
                portas.insert(0, str(PORTA_SISTEMA))

            acesso = _carregar(self._acc_path, {})
            acesso.update({
                'modo': modo,
                'portas': portas,
                'configurado_em': _agora()
            })
            _salvar(self._acc_path, acesso)
            return {'sucesso': True,
                    'mensagem': 'VPN de acesso configurada',
                    'modo': modo, 'portas': portas}
        except Exception as e:
            logger.error(f"configurar_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def status_vpn_acesso(self):
        try:
            acesso = _carregar(self._acc_path, {})

            # verificar se openvpn server está rodando
            r = _cmd('pgrep -f "openvpn.*rrfs-acesso"', timeout=5)
            rodando = r['sucesso'] and bool(r['saida'])

            return {
                'sucesso': True,
                'ativa': acesso.get('ativa', False),
                'rodando': rodando,
                'modo': acesso.get('modo', ''),
                'portas': acesso.get('portas', []),
                'ip_publico_servidor': self._ip_publico_servidor(),
                'configurado_em': acesso.get('configurado_em', '')
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
            logger.error(f"_ip_publico_servidor: {e}")
            return 'N/A'

    def ativar_vpn_acesso(self):
        """
        Ativa o servidor OpenVPN de acesso.
        Gera PKI, configura servidor, aplica UFW.
        """
        try:
            acesso = _carregar(self._acc_path, {})
            modo   = acesso.get('modo', 'ip_publico')
            portas = acesso.get('portas', [str(PORTA_SISTEMA)])

            # verificar openvpn
            r = _cmd('which openvpn', timeout=5)
            if not r['sucesso']:
                r2 = _cmd(
                    'apt-get install -y openvpn easy-rsa',
                    timeout=300
                )
                if not r2['sucesso']:
                    return {'sucesso': False,
                            'erro': 'Falha ao instalar OpenVPN'}

            pki_dir = self.ovpn_dir / 'pki'
            srv_cfg = self.ovpn_dir / 'server.conf'

            # gerar PKI se não existir
            if not pki_dir.exists():
                resultado_pki = self._gerar_pki(pki_dir)
                if not resultado_pki:
                    return {'sucesso': False,
                            'erro': 'Falha ao gerar PKI'}

            # configuração do servidor
            ip_publico = self._ip_publico_servidor()
            porta_vpn  = 1194

            if modo == 'tor':
                # obter endereço onion
                onion = self._obter_onion_tor_vpn()
                servidor_addr = onion or ip_publico
            else:
                servidor_addr = ip_publico

            self._gerar_config_servidor(
                srv_cfg, pki_dir, porta_vpn, portas
            )

            # iniciar servidor
            log_f = str(self.ovpn_dir / 'server.log')
            pid_f = str(self.ovpn_dir / 'server.pid')

            _cmd('pkill -f "openvpn.*rrfs-acesso"', timeout=5)
            time.sleep(1)

            cmd = (
                f'openvpn '
                f'--config {srv_cfg} '
                f'--daemon openvpn-rrfs-acesso '
                f'--log {log_f} '
                f'--writepid {pid_f}'
            )
            r = _cmd(cmd, timeout=30)

            time.sleep(3)

            # verificar se está rodando
            r_pid = _cmd('pgrep -f "openvpn-rrfs-acesso"',
                          timeout=5)
            if not r_pid['sucesso']:
                log_txt = ''
                try:
                    log_txt = Path(log_f).read_text()
                except Exception:
                    pass
                return {
                    'sucesso': False,
                    'erro': f'Servidor não iniciou: {log_txt[-300:]}'
                }

            # UFW: liberar porta VPN + portas de acesso
            if self._firewall:
                from modulos.firewall_ufw import FirewallUFW
                self._firewall.adicionar_regra_automatica(
                    'VPNAcesso:porta_vpn',
                    {
                        'nome': 'VPN Acesso: porta OpenVPN',
                        'interface': '',
                        'direcao': 'in',
                        'protocolo': 'udp',
                        'ip': '',
                        'porta': str(porta_vpn)
                    },
                    FirewallUFW.CAT_VPN
                )
                for porta in portas:
                    self._firewall.adicionar_regra_automatica(
                        f'VPNAcesso:p{porta}',
                        {
                            'nome': f'VPN Acesso: porta {porta}',
                            'interface': '',
                            'direcao': 'in',
                            'protocolo': 'tcp',
                            'ip': '',
                            'porta': str(porta)
                        },
                        FirewallUFW.CAT_VPN
                    )

            acesso['ativa']         = True
            acesso['porta_vpn']     = porta_vpn
            acesso['ip_publico']    = ip_publico
            acesso['servidor_addr'] = servidor_addr
            acesso['ativado_em']    = _agora()
            _salvar(self._acc_path, acesso)

            return {
                'sucesso': True,
                'mensagem': 'Servidor VPN de acesso ativado!',
                'servidor_addr': servidor_addr,
                'porta_vpn': porta_vpn,
                'modo': modo
            }
        except Exception as e:
            logger.error(f"ativar_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def desativar_vpn_acesso(self):
        try:
            _cmd('pkill -f "openvpn-rrfs-acesso"', timeout=5)
            time.sleep(1)
            _cmd('pkill -9 -f "openvpn-rrfs-acesso"', timeout=5)

            acesso = _carregar(self._acc_path, {})
            acesso['ativa'] = False
            _salvar(self._acc_path, acesso)

            if self._firewall:
                self._firewall.remover_regras_vpn('VPNAcesso:')

            return {'sucesso': True,
                    'mensagem': 'Servidor VPN de acesso desativado'}
        except Exception as e:
            logger.error(f"desativar_vpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _gerar_pki(self, pki_dir):
        """Gera PKI simplificada para o servidor VPN"""
        try:
            pki_dir.mkdir(parents=True, exist_ok=True)

            # CA
            _cmd(
                f'openssl genrsa -out {pki_dir}/ca.key 4096',
                timeout=60
            )
            _cmd(
                f'openssl req -new -x509 -days 3650 '
                f'-key {pki_dir}/ca.key '
                f'-out {pki_dir}/ca.crt '
                f'-subj "/CN=RRFS-CA"',
                timeout=60
            )

            # Servidor
            _cmd(
                f'openssl genrsa -out {pki_dir}/server.key 4096',
                timeout=60
            )
            _cmd(
                f'openssl req -new '
                f'-key {pki_dir}/server.key '
                f'-out {pki_dir}/server.csr '
                f'-subj "/CN=RRFS-Server"',
                timeout=30
            )
            _cmd(
                f'openssl x509 -req -days 3650 '
                f'-in {pki_dir}/server.csr '
                f'-CA {pki_dir}/ca.crt '
                f'-CAkey {pki_dir}/ca.key '
                f'-CAcreateserial '
                f'-out {pki_dir}/server.crt',
                timeout=60
            )

            # Cliente
            _cmd(
                f'openssl genrsa -out {pki_dir}/client.key 4096',
                timeout=60
            )
            _cmd(
                f'openssl req -new '
                f'-key {pki_dir}/client.key '
                f'-out {pki_dir}/client.csr '
                f'-subj "/CN=RRFS-Client"',
                timeout=30
            )
            _cmd(
                f'openssl x509 -req -days 3650 '
                f'-in {pki_dir}/client.csr '
                f'-CA {pki_dir}/ca.crt '
                f'-CAkey {pki_dir}/ca.key '
                f'-CAcreateserial '
                f'-out {pki_dir}/client.crt',
                timeout=60
            )

            # DH
            _cmd(
                f'openssl dhparam -out {pki_dir}/dh.pem 2048',
                timeout=180
            )

            # TLS Auth
            _cmd(
                f'openvpn --genkey secret {pki_dir}/ta.key',
                timeout=30
            )

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
"""
            # push routes para portas de acesso
            for porta_acesso in portas_acesso:
                conteudo += (
                    f'push "route 10.8.0.1 '
                    f'255.255.255.255"\n'
                )

            Path(cfg_path).write_text(conteudo)
            os.chmod(str(cfg_path), 0o600)
        except Exception as e:
            logger.error(f"gerar_config_servidor: {e}")

    def gerar_ovpn_acesso(self):
        """Gera arquivo .ovpn para o cliente baixar"""
        try:
            acesso  = _carregar(self._acc_path, {})
            pki_dir = self.ovpn_dir / 'pki'

            if not pki_dir.exists():
                return {'sucesso': False,
                        'erro': 'PKI não gerada. Ative a VPN primeiro.'}

            modo      = acesso.get('modo', 'ip_publico')
            porta_vpn = acesso.get('porta_vpn', 1194)

            if modo == 'tor':
                addr = acesso.get('servidor_addr', '')
                if not addr or '.onion' not in addr:
                    return {'sucesso': False,
                            'erro': 'Endereço .onion não disponível'}
                remote_line = (
                    f'remote {addr} {porta_vpn}\n'
                    f'socks-proxy 127.0.0.1 9050\n'
                )
            else:
                ip = acesso.get('ip_publico', '')
                if not ip or ip == 'N/A':
                    return {'sucesso': False,
                            'erro': 'IP público não disponível'}
                remote_line = f'remote {ip} {porta_vpn}\n'

            # ler certificados
            def ler(nome):
                p = pki_dir / nome
                return p.read_text() if p.exists() else ''

            ca_crt     = ler('ca.crt')
            client_crt = ler('client.crt')
            client_key = ler('client.key')
            ta_key     = ler('ta.key')

            ovpn = f"""client
dev tun
proto udp
{remote_line}
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
verb 3
key-direction 1
<ca>
{ca_crt}</ca>
<cert>
{client_crt}</cert>
<key>
{client_key}</key>
<tls-auth>
{ta_key}</tls-auth>
"""
            ovpn_path = self.ovpn_dir / 'cliente.ovpn'
            ovpn_path.write_text(ovpn)
            os.chmod(str(ovpn_path), 0o600)

            return {'sucesso': True, 'arquivo': str(ovpn_path)}
        except Exception as e:
            logger.error(f"gerar_ovpn_acesso: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _obter_onion_tor_vpn(self):
        """Obtém endereço .onion para a VPN de acesso via Tor"""
        try:
            from modulos.tor_manager import TorManager
            tor = TorManager(str(self.base_dir))
            for s in tor.config.get('servicos', []):
                if 'vpn' in s.get('nome', '').lower() or \
                   s.get('porta_destino') == 1194:
                    onion = tor._ler_onion(s.get('dir_id', ''))
                    if onion:
                        return onion
        except Exception as e:
            logger.error(f"obter_onion_tor_vpn: {e}")
        return ''
