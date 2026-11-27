#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AppArmor (Debian) / SELinux - RRFS Servidores v2.1
CORRIGIDO v2.1:
  - Perfil AppArmor customizado para Tor (hidden services RRFS)
  - Perfil AppArmor customizado para OpenVPN (arquivos RRFS)
  - Perfil AppArmor customizado para UFW
  - aa-enforce SÓ em perfis que não quebram o sistema
  - Não coloca Flask/Python em enforce (quebraria o RRFS)
"""

import os
import re
import json
import logging
from datetime import datetime

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.SELinux')


class SELinuxManager:

    def __init__(self, base_dir):
        self.base_dir  = base_dir
        self._cfg_path = os.path.join(
            base_dir, 'dados', 'selinux_config.json'
        )
        self._config   = self._carregar()

    def _carregar(self):
        try:
            if os.path.exists(self._cfg_path):
                with open(self._cfg_path, 'r') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"selinux carregar: {e}")
        return {'motor': 'apparmor', 'ativo': False}

    def _salvar(self):
        try:
            os.makedirs(
                os.path.dirname(self._cfg_path), exist_ok=True
            )
            with open(self._cfg_path, 'w') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"selinux salvar: {e}")

    def _detectar_motor(self):
        r = executar_comando('which apparmor_status 2>/dev/null')
        if r['sucesso']:
            return 'apparmor'
        r = executar_comando(
            'dpkg -l apparmor 2>/dev/null | grep "^ii"'
        )
        if r['sucesso']:
            return 'apparmor'
        r = executar_comando('which sestatus 2>/dev/null')
        if r['sucesso']:
            return 'selinux'
        return 'nenhum'

    # ══════════════════════════════════════════════════════
    # STATUS
    # ══════════════════════════════════════════════════════

    def obter_status(self):
        try:
            motor = self._detectar_motor()
            if motor == 'apparmor':
                return self._status_apparmor()
            elif motor == 'selinux':
                return self._status_selinux()
            else:
                return {
                    'motor':     'nenhum',
                    'instalado': False,
                    'ativo':     False,
                    'modo':      '--',
                    'mensagem':  'AppArmor não instalado.',
                    'perfis':    []
                }
        except Exception as e:
            logger.error(f"selinux obter_status: {e}")
            return {'motor': 'erro', 'ativo': False}

    def _status_apparmor(self):
        try:
            r = executar_comando(
                'systemctl is-active apparmor 2>/dev/null'
            )
            ativo = r['sucesso'] and 'active' in r.get('saida', '')

            r2 = executar_comando(
                'apparmor_status 2>/dev/null || aa-status 2>/dev/null',
                timeout=10
            )
            texto = r2.get('saida', '')

            perfis_enforce  = 0
            perfis_complain = 0
            processos       = 0

            m = re.search(r'(\d+) profiles? are in enforce mode', texto)
            if m:
                perfis_enforce = int(m.group(1))

            m = re.search(r'(\d+) profiles? are in complain mode', texto)
            if m:
                perfis_complain = int(m.group(1))

            m = re.search(r'(\d+) processes? have profiles?', texto)
            if m:
                processos = int(m.group(1))

            grub_ok = False
            try:
                with open('/etc/default/grub', 'r') as f:
                    grub_content = f.read()
                grub_ok = 'apparmor=1' in grub_content
            except Exception:
                pass

            r3 = executar_comando(
                'cat /sys/module/apparmor/parameters/enabled 2>/dev/null'
            )
            kernel_aa = r3['sucesso'] and 'Y' in r3.get('saida', '')

            precisa_reiniciar = not kernel_aa and not grub_ok

            return {
                'motor':             'apparmor',
                'instalado':         True,
                'ativo':             ativo,
                'modo':              'enforce' if ativo else 'disabled',
                'perfis_enforce':    perfis_enforce,
                'perfis_complain':   perfis_complain,
                'processos':         processos,
                'texto_completo':    texto[:500],
                'perfis':            self._listar_perfis_aa(),
                'precisa_reiniciar': precisa_reiniciar,
            }
        except Exception as e:
            logger.error(f"_status_apparmor: {e}")
            return {'motor': 'apparmor', 'ativo': False}

    def _status_selinux(self):
        try:
            r    = executar_comando('sestatus 2>/dev/null', timeout=10)
            texto = r.get('saida', '')
            ativo = 'enabled' in texto.lower()
            modo  = 'enforcing'
            m = re.search(r'Current mode:\s*(\w+)', texto)
            if m:
                modo = m.group(1)
            return {
                'motor':          'selinux',
                'instalado':      True,
                'ativo':          ativo,
                'modo':           modo,
                'texto_completo': texto,
                'perfis':         []
            }
        except Exception as e:
            logger.error(f"_status_selinux: {e}")
            return {'motor': 'selinux', 'ativo': False}

    def _listar_perfis_aa(self):
        try:
            r = executar_comando('aa-status --json 2>/dev/null', timeout=10)
            if r['sucesso'] and r['saida']:
                try:
                    dados  = json.loads(r['saida'])
                    perfis = []
                    for nome, modo in dados.get('profiles', {}).items():
                        perfis.append({'nome': nome, 'modo': modo})
                    return perfis[:50]
                except Exception:
                    pass

            r2 = executar_comando(
                'ls /etc/apparmor.d/ 2>/dev/null | head -30'
            )
            perfis = []
            if r2['sucesso']:
                for p in r2['saida'].splitlines():
                    p = p.strip()
                    if p and not p.startswith('#'):
                        perfis.append({'nome': p, 'modo': 'enforce'})
            return perfis
        except Exception as e:
            logger.error(f"_listar_perfis_aa: {e}")
            return []

    # ══════════════════════════════════════════════════════
    # ATIVAR
    # ══════════════════════════════════════════════════════

    def ativar(self):
        try:
            motor = self._detectar_motor()

            if motor == 'nenhum':
                r = executar_comando(
                    'apt-get install -y '
                    'apparmor apparmor-utils '
                    'apparmor-profiles apparmor-profiles-extra',
                    timeout=300
                )
                if not r['sucesso']:
                    return {'sucesso': False, 'erro': 'Falha ao instalar AppArmor'}

            if motor in ('apparmor', 'nenhum'):
                self._configurar_grub_apparmor()

                executar_comando('systemctl enable apparmor', timeout=10)
                r = executar_comando('systemctl start apparmor', timeout=30)

                # CORRIGIDO v2.1:
                # Instalar perfis RRFS customizados ANTES de enforce
                self._instalar_perfis_rrfs()

                # enforce SELETIVO: apenas perfis que não quebram o RRFS
                self._aplicar_enforce_seguro()

                self._config['ativo'] = True
                self._config['motor'] = 'apparmor'
                self._salvar()

                return {
                    'sucesso': True,
                    'mensagem': (
                        'AppArmor ativado com perfis RRFS! '
                        'Tor, VPN e UFW funcionarão corretamente. '
                        'Reinicie para efeito completo no kernel.'
                    )
                }

            elif motor == 'selinux':
                r = executar_comando('setenforce 1 2>/dev/null', timeout=10)
                self._config['ativo'] = True
                self._salvar()
                return {'sucesso': True, 'mensagem': 'SELinux ativado (enforce).'}

        except Exception as e:
            logger.error(f"selinux ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # PERFIS RRFS CUSTOMIZADOS
    # ══════════════════════════════════════════════════════

    def _instalar_perfis_rrfs(self):
        """
        NOVO v2.1:
        Instala perfis AppArmor customizados para:
        - Tor: permite acesso aos hidden services do RRFS
        - OpenVPN: permite acesso aos arquivos .ovpn do RRFS
        - UFW: não interferir nas regras do firewall RRFS

        Sem estes perfis, o AppArmor em enforce bloqueia
        tor e openvpn de acessar os diretórios do RRFS.
        """
        try:
            base_dir = self.base_dir

            # ── Perfil Tor ────────────────────────────────
            # Extende o perfil padrão do tor para incluir
            # os diretórios de hidden services do RRFS
            perfil_tor = f"""\
# RRFS - Perfil AppArmor para Tor
# Extende o perfil padrão permitindo hidden services do RRFS
# v2.1

#include <tunables/global>

/usr/bin/tor {{
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Permissões padrão do Tor
  capability setuid,
  capability setgid,
  capability net_bind_service,
  capability dac_override,
  capability dac_read_search,

  # Logs e PID
  /var/log/tor/             rw,
  /var/log/tor/**           rw,
  /var/run/tor/             rw,
  /var/run/tor/**           rw,
  /run/tor/                 rw,
  /run/tor/**               rw,

  # Configuração
  /etc/tor/                 r,
  /etc/tor/**               r,
  /usr/share/tor/           r,
  /usr/share/tor/**         r,

  # Diretório padrão de hidden services
  /var/lib/tor/             rwk,
  /var/lib/tor/**           rwk,

  # RRFS: hidden services no caminho customizado
  {base_dir}/dados/         r,
  /var/lib/tor/hidden_service_hs_*/   rwk,
  /var/lib/tor/hidden_service_hs_*/** rwk,

  # Rede
  network tcp,
  network udp,

  # Binário
  /usr/bin/tor              mr,
  /usr/lib/tor/**           mr,

  # Misc
  /proc/sys/kernel/random/uuid r,
  /dev/urandom              r,
  /dev/random               r,
}}
"""

            # ── Perfil OpenVPN ────────────────────────────
            # Extende o perfil padrão permitindo arquivos
            # .ovpn e auth do RRFS
            perfil_openvpn = f"""\
# RRFS - Perfil AppArmor para OpenVPN
# Extende o perfil padrão permitindo arquivos VPN do RRFS
# v2.1

#include <tunables/global>

/usr/sbin/openvpn {{
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  # Permissões padrão do OpenVPN
  capability net_admin,
  capability net_raw,
  capability setuid,
  capability setgid,
  capability dac_override,
  capability dac_read_search,
  capability mknod,
  capability sys_module,

  # Dispositivos de rede
  /dev/net/tun              rw,
  /dev/urandom              r,
  /dev/random               r,

  # Configuração padrão do OpenVPN
  /etc/openvpn/             r,
  /etc/openvpn/**           r,

  # RRFS: arquivos VPN no diretório de dados
  {base_dir}/dados/conexao/vpns/         r,
  {base_dir}/dados/conexao/vpns/**       r,
  {base_dir}/dados/conexao/ovpn_acesso/  r,
  {base_dir}/dados/conexao/ovpn_acesso/** r,
  {base_dir}/dados/conexao/openvpn.log  rw,
  {base_dir}/dados/conexao/openvpn.pid  rw,
  {base_dir}/dados/conexao/server.log   rw,
  {base_dir}/dados/conexao/server.pid   rw,

  # Logs
  /var/log/openvpn/         rw,
  /var/log/openvpn/**       rw,
  /tmp/                     rw,
  /tmp/**                   rw,
  /run/openvpn/             rw,
  /run/openvpn/**           rw,

  # PKI - certificados
  {base_dir}/dados/conexao/ovpn_acesso/pki/ r,
  {base_dir}/dados/conexao/ovpn_acesso/pki/** r,

  # Rede
  network tcp,
  network udp,

  # Binário
  /usr/sbin/openvpn         mr,
  /usr/lib/openvpn/**       mr,

  # Scripts auxiliares (script-security 1 = apenas built-in)
  /bin/sh                   ix,
  /bin/bash                 ix,

  # Misc
  /proc/sys/net/**          rw,
  /proc/sys/kernel/random/uuid r,
  /sys/class/net/           r,
  /sys/class/net/**         r,
}}
"""

            # ── Perfil UFW / iptables ─────────────────────
            # UFW e iptables precisam de acesso total à rede
            # O perfil padrão pode ser muito restritivo
            perfil_ufw = """\
# RRFS - Perfil AppArmor para UFW/iptables
# Garante que UFW funciona sem restrições do AppArmor
# v2.1

#include <tunables/global>

/usr/sbin/ufw {
  #include <abstractions/base>

  capability net_admin,
  capability net_raw,
  capability sys_admin,
  capability dac_override,
  capability dac_read_search,

  # UFW precisa ler/escrever suas regras
  /etc/ufw/                 rw,
  /etc/ufw/**               rw,
  /lib/ufw/                 r,
  /lib/ufw/**               r,
  /var/lib/ufw/             rw,
  /var/lib/ufw/**           rw,

  # Executar iptables
  /sbin/iptables            ix,
  /usr/sbin/iptables        ix,
  /sbin/iptables-restore    ix,
  /usr/sbin/iptables-restore ix,
  /sbin/ip6tables           ix,
  /usr/sbin/ip6tables       ix,
  /sbin/ip6tables-restore   ix,
  /usr/sbin/ip6tables-restore ix,

  # Python para scripts UFW
  /usr/bin/python3*         ix,
  /usr/lib/python3/**       r,

  # Proc
  /proc/sys/net/**          rw,
  /proc/net/**              r,

  # Misc
  /run/ufw.lock             rw,
  /tmp/**                   rw,
}

/sbin/iptables {
  #include <abstractions/base>
  capability net_admin,
  capability net_raw,
  /proc/net/**              r,
  /proc/sys/net/**          rw,
  network,
}

/usr/sbin/iptables {
  #include <abstractions/base>
  capability net_admin,
  capability net_raw,
  /proc/net/**              r,
  /proc/sys/net/**          rw,
  network,
}
"""

            # Salvar perfis
            aa_dir = '/etc/apparmor.d'
            os.makedirs(aa_dir, exist_ok=True)

            perfis = [
                (f'{aa_dir}/usr.bin.tor.rrfs',        perfil_tor),
                (f'{aa_dir}/usr.sbin.openvpn.rrfs',   perfil_openvpn),
                (f'{aa_dir}/rrfs-ufw-iptables',        perfil_ufw),
            ]

            for path, conteudo in perfis:
                try:
                    with open(path, 'w') as f:
                        f.write(conteudo)
                    os.chmod(path, 0o644)
                    # Carregar perfil sem enforce ainda
                    executar_comando(
                        f'apparmor_parser -r "{path}" 2>/dev/null',
                        timeout=15
                    )
                    logger.error(f"Perfil RRFS instalado: {path}")
                except Exception as e:
                    logger.error(f"Instalar perfil {path}: {e}")

        except Exception as e:
            logger.error(f"_instalar_perfis_rrfs: {e}")

    def _aplicar_enforce_seguro(self):
        """
        CORRIGIDO v2.1:
        Aplica enforce SELETIVO:
        - Perfis RRFS customizados: enforce (Tor, OpenVPN, UFW)
        - Perfis do sistema conhecidos: enforce
        - NÃO coloca Python/Flask em enforce (quebraria o RRFS)
        - NÃO coloca NetworkManager em enforce (interfere nas conexões)
        """
        try:
            # Perfis seguros para enforce
            # (não interferem no RRFS)
            perfis_enforce_seguro = [
                # Rede e sistema
                '/etc/apparmor.d/usr.sbin.apache2',
                '/etc/apparmor.d/usr.sbin.nginx',
                '/etc/apparmor.d/usr.sbin.mysqld',
                '/etc/apparmor.d/usr.sbin.sshd',
                '/etc/apparmor.d/usr.bin.man',
                '/etc/apparmor.d/usr.sbin.rsyslogd',
                # RRFS customizados
                '/etc/apparmor.d/usr.bin.tor.rrfs',
                '/etc/apparmor.d/usr.sbin.openvpn.rrfs',
                '/etc/apparmor.d/rrfs-ufw-iptables',
            ]

            # Perfis para colocar em COMPLAIN (não bloquear, só logar)
            # Inclui tudo que pode interferir no RRFS
            perfis_complain = [
                '/etc/apparmor.d/usr.bin.python3*',
                '/etc/apparmor.d/usr.sbin.NetworkManager',
                '/etc/apparmor.d/sbin.dhclient',
                '/etc/apparmor.d/usr.sbin.openvpn',  # usar o .rrfs
                '/etc/apparmor.d/usr.bin.tor',        # usar o .rrfs
            ]

            for perfil in perfis_enforce_seguro:
                if os.path.exists(perfil):
                    executar_comando(
                        f'aa-enforce "{perfil}" 2>/dev/null',
                        timeout=10
                    )

            for perfil in perfis_complain:
                # glob expand
                import glob
                for p in glob.glob(perfil):
                    if os.path.exists(p):
                        executar_comando(
                            f'aa-complain "{p}" 2>/dev/null',
                            timeout=10
                        )

        except Exception as e:
            logger.error(f"_aplicar_enforce_seguro: {e}")

    # ══════════════════════════════════════════════════════
    # DESATIVAR
    # ══════════════════════════════════════════════════════

    def desativar(self):
        try:
            motor = self._detectar_motor()

            if motor == 'apparmor':
                executar_comando('systemctl stop apparmor', timeout=15)
                executar_comando('aa-teardown 2>/dev/null', timeout=15)
                self._remover_grub_apparmor()
                self._config['ativo'] = False
                self._salvar()
                return {
                    'sucesso': True,
                    'mensagem': (
                        'AppArmor desativado. '
                        'Reinicie para efeito completo.'
                    )
                }
            elif motor == 'selinux':
                executar_comando('setenforce 0 2>/dev/null', timeout=10)
                self._config['ativo'] = False
                self._salvar()
                return {
                    'sucesso': True,
                    'mensagem': 'SELinux em modo permissivo.'
                }

            return {'sucesso': False, 'erro': 'Nenhum motor encontrado'}
        except Exception as e:
            logger.error(f"selinux desativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # GERENCIAR PERFIS
    # ══════════════════════════════════════════════════════

    def listar_perfis(self):
        return self._listar_perfis_aa()

    def gerenciar_perfil(self, perfil, acao):
        try:
            cmds = {
                'enforce':  f'aa-enforce /etc/apparmor.d/{perfil}',
                'complain': f'aa-complain /etc/apparmor.d/{perfil}',
                'disable':  f'aa-disable /etc/apparmor.d/{perfil}',
            }
            cmd = cmds.get(acao)
            if not cmd:
                return {'sucesso': False, 'erro': 'Ação inválida'}

            r = executar_comando(cmd, timeout=15)
            if r['sucesso']:
                return {'sucesso': True, 'mensagem': f'Perfil {perfil}: {acao}'}
            return {'sucesso': False, 'erro': r.get('erro', 'Falha')}
        except Exception as e:
            logger.error(f"selinux gerenciar_perfil: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # GRUB
    # ══════════════════════════════════════════════════════

    def _configurar_grub_apparmor(self):
        try:
            grub_file = '/etc/default/grub'
            if not os.path.exists(grub_file):
                return

            with open(grub_file, 'r') as f:
                conteudo = f.read()

            param = 'apparmor=1 security=apparmor'
            if param in conteudo:
                return

            novo = re.sub(
                r'(GRUB_CMDLINE_LINUX="[^"]*)"',
                lambda m: m.group(0)[:-1] + f' {param}"',
                conteudo
            )

            if novo == conteudo:
                novo += f'\nGRUB_CMDLINE_LINUX="{param}"\n'

            with open(grub_file, 'w') as f:
                f.write(novo)

            executar_comando('update-grub 2>/dev/null', timeout=30)

        except Exception as e:
            logger.error(f"_configurar_grub_apparmor: {e}")

    def _remover_grub_apparmor(self):
        try:
            grub_file = '/etc/default/grub'
            if not os.path.exists(grub_file):
                return

            with open(grub_file, 'r') as f:
                conteudo = f.read()

            novo = conteudo.replace(
                ' apparmor=1 security=apparmor', ''
            ).replace(
                'apparmor=1 security=apparmor', ''
            )

            with open(grub_file, 'w') as f:
                f.write(novo)

            executar_comando('update-grub 2>/dev/null', timeout=30)
        except Exception as e:
            logger.error(f"_remover_grub_apparmor: {e}")
