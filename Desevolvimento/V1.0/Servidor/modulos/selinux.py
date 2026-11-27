#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AppArmor (Debian) / SELinux - RRFS Servidores v2.2
v2.2: removido o perfil OpenVPN (conexao.py/VPN descontinuado) e
      limpeza do perfil antigo se existir.
"""

import os
import re
import glob
import json
import logging

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.SELinux')

PERFIL_OPENVPN_LEGADO = '/etc/apparmor.d/usr.sbin.openvpn.rrfs'


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
            os.makedirs(os.path.dirname(self._cfg_path), exist_ok=True)
            with open(self._cfg_path, 'w') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"selinux salvar: {e}")

    def _detectar_motor(self):
        if executar_comando('which apparmor_status 2>/dev/null')['sucesso']:
            return 'apparmor'
        if executar_comando(
                'dpkg -l apparmor 2>/dev/null | grep "^ii"')['sucesso']:
            return 'apparmor'
        if executar_comando('which sestatus 2>/dev/null')['sucesso']:
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
            if motor == 'selinux':
                return self._status_selinux()
            return {'motor': 'nenhum', 'instalado': False,
                    'ativo': False, 'modo': '--',
                    'mensagem': 'AppArmor não instalado.',
                    'perfis': []}
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

            def _n(padrao):
                m = re.search(padrao, texto)
                return int(m.group(1)) if m else 0

            grub_ok = False
            try:
                with open('/etc/default/grub', 'r') as f:
                    grub_ok = 'apparmor=1' in f.read()
            except Exception:
                pass

            r3 = executar_comando(
                'cat /sys/module/apparmor/parameters/enabled 2>/dev/null'
            )
            kernel_aa = r3['sucesso'] and 'Y' in r3.get('saida', '')

            return {
                'motor':             'apparmor',
                'instalado':         True,
                'ativo':             ativo,
                'modo':              'enforce' if ativo else 'disabled',
                'perfis_enforce':    _n(r'(\d+) profiles? are in enforce mode'),
                'perfis_complain':   _n(r'(\d+) profiles? are in complain mode'),
                'processos':         _n(r'(\d+) processes? have profiles?'),
                'texto_completo':    texto[:500],
                'perfis':            self._listar_perfis_aa(),
                'precisa_reiniciar': not kernel_aa and not grub_ok,
            }
        except Exception as e:
            logger.error(f"_status_apparmor: {e}")
            return {'motor': 'apparmor', 'ativo': False}

    def _status_selinux(self):
        try:
            r = executar_comando('sestatus 2>/dev/null', timeout=10)
            texto = r.get('saida', '')
            modo = 'enforcing'
            m = re.search(r'Current mode:\s*(\w+)', texto)
            if m:
                modo = m.group(1)
            return {'motor': 'selinux', 'instalado': True,
                    'ativo': 'enabled' in texto.lower(), 'modo': modo,
                    'texto_completo': texto, 'perfis': []}
        except Exception as e:
            logger.error(f"_status_selinux: {e}")
            return {'motor': 'selinux', 'ativo': False}

    def _listar_perfis_aa(self):
        try:
            r = executar_comando('aa-status --json 2>/dev/null',
                                 timeout=10)
            if r['sucesso'] and r['saida']:
                try:
                    dados = json.loads(r['saida'])
                    return [{'nome': n, 'modo': m}
                            for n, m in
                            dados.get('profiles', {}).items()][:50]
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
                    'apt-get install -y apparmor apparmor-utils '
                    'apparmor-profiles apparmor-profiles-extra',
                    timeout=300
                )
                if not r['sucesso']:
                    return {'sucesso': False,
                            'erro': 'Falha ao instalar AppArmor'}

            if motor in ('apparmor', 'nenhum'):
                self._configurar_grub_apparmor()
                executar_comando('systemctl enable apparmor', timeout=10)
                executar_comando('systemctl start apparmor', timeout=30)

                self._remover_perfil_openvpn_legado()
                self._instalar_perfis_rrfs()
                self._aplicar_enforce_seguro()

                self._config['ativo'] = True
                self._config['motor'] = 'apparmor'
                self._salvar()
                return {
                    'sucesso': True,
                    'mensagem': ('AppArmor ativado com perfis RRFS '
                                 '(Tor e UFW). Reinicie para efeito '
                                 'completo no kernel.')
                }

            if motor == 'selinux':
                executar_comando('setenforce 1 2>/dev/null', timeout=10)
                self._config['ativo'] = True
                self._salvar()
                return {'sucesso': True,
                        'mensagem': 'SELinux ativado (enforce).'}

        except Exception as e:
            logger.error(f"selinux ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # PERFIS RRFS
    # ══════════════════════════════════════════════════════

    def _remover_perfil_openvpn_legado(self):
        """Descarrega e apaga o perfil criado por versões anteriores."""
        try:
            if os.path.exists(PERFIL_OPENVPN_LEGADO):
                executar_comando(
                    f'apparmor_parser -R "{PERFIL_OPENVPN_LEGADO}" '
                    f'2>/dev/null', timeout=15
                )
                os.remove(PERFIL_OPENVPN_LEGADO)
        except Exception as e:
            logger.error(f"_remover_perfil_openvpn_legado: {e}")

    def _instalar_perfis_rrfs(self):
        """Perfis para Tor (hidden services RRFS) e UFW/iptables."""
        try:
            base_dir = self.base_dir

            perfil_tor = f"""\
# RRFS - Perfil AppArmor para Tor
# v2.2

#include <tunables/global>

/usr/bin/tor {{
  #include <abstractions/base>
  #include <abstractions/nameservice>
  #include <abstractions/openssl>

  capability setuid,
  capability setgid,
  capability net_bind_service,
  capability dac_override,
  capability dac_read_search,

  /var/log/tor/             rw,
  /var/log/tor/**           rw,
  /var/run/tor/             rw,
  /var/run/tor/**           rw,
  /run/tor/                 rw,
  /run/tor/**               rw,

  /etc/tor/                 r,
  /etc/tor/**               r,
  /usr/share/tor/           r,
  /usr/share/tor/**         r,

  /var/lib/tor/             rwk,
  /var/lib/tor/**           rwk,

  {base_dir}/dados/         r,
  /var/lib/tor/hidden_service_hs_*/   rwk,
  /var/lib/tor/hidden_service_hs_*/** rwk,

  network tcp,
  network udp,

  /usr/bin/tor              mr,
  /usr/lib/tor/**           mr,

  /proc/sys/kernel/random/uuid r,
  /dev/urandom              r,
  /dev/random               r,
}}
"""

            perfil_ufw = """\
# RRFS - Perfil AppArmor para UFW/iptables
# v2.2

#include <tunables/global>

/usr/sbin/ufw {
  #include <abstractions/base>

  capability net_admin,
  capability net_raw,
  capability sys_admin,
  capability dac_override,
  capability dac_read_search,

  /etc/ufw/                 rw,
  /etc/ufw/**               rw,
  /lib/ufw/                 r,
  /lib/ufw/**               r,
  /var/lib/ufw/             rw,
  /var/lib/ufw/**           rw,

  /sbin/iptables            ix,
  /usr/sbin/iptables        ix,
  /sbin/iptables-restore    ix,
  /usr/sbin/iptables-restore ix,
  /sbin/ip6tables           ix,
  /usr/sbin/ip6tables       ix,
  /sbin/ip6tables-restore   ix,
  /usr/sbin/ip6tables-restore ix,

  /usr/bin/python3*         ix,
  /usr/lib/python3/**       r,

  /proc/sys/net/**          rw,
  /proc/net/**              r,

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

            aa_dir = '/etc/apparmor.d'
            os.makedirs(aa_dir, exist_ok=True)

            for path, conteudo in [
                (f'{aa_dir}/usr.bin.tor.rrfs',   perfil_tor),
                (f'{aa_dir}/rrfs-ufw-iptables',  perfil_ufw),
            ]:
                try:
                    with open(path, 'w') as f:
                        f.write(conteudo)
                    os.chmod(path, 0o644)
                    executar_comando(
                        f'apparmor_parser -r "{path}" 2>/dev/null',
                        timeout=15
                    )
                except Exception as e:
                    logger.error(f"Instalar perfil {path}: {e}")

        except Exception as e:
            logger.error(f"_instalar_perfis_rrfs: {e}")

    def _aplicar_enforce_seguro(self):
        """
        enforce seletivo. Python/Flask (onde roda o RRFS e o Tox) e
        NetworkManager ficam em complain para não quebrar o painel.
        """
        try:
            enforce = [
                '/etc/apparmor.d/usr.sbin.apache2',
                '/etc/apparmor.d/usr.sbin.nginx',
                '/etc/apparmor.d/usr.sbin.mysqld',
                '/etc/apparmor.d/usr.sbin.sshd',
                '/etc/apparmor.d/usr.bin.man',
                '/etc/apparmor.d/usr.sbin.rsyslogd',
                '/etc/apparmor.d/usr.bin.tor.rrfs',
                '/etc/apparmor.d/rrfs-ufw-iptables',
            ]
            complain = [
                '/etc/apparmor.d/usr.bin.python3*',
                '/etc/apparmor.d/usr.sbin.NetworkManager',
                '/etc/apparmor.d/sbin.dhclient',
                '/etc/apparmor.d/usr.bin.tor',
            ]
            for perfil in enforce:
                if os.path.exists(perfil):
                    executar_comando(
                        f'aa-enforce "{perfil}" 2>/dev/null',
                        timeout=10
                    )
            for perfil in complain:
                for p in glob.glob(perfil):
                    executar_comando(
                        f'aa-complain "{p}" 2>/dev/null', timeout=10
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
                return {'sucesso': True,
                        'mensagem': ('AppArmor desativado. '
                                     'Reinicie para efeito completo.')}
            if motor == 'selinux':
                executar_comando('setenforce 0 2>/dev/null', timeout=10)
                self._config['ativo'] = False
                self._salvar()
                return {'sucesso': True,
                        'mensagem': 'SELinux em modo permissivo.'}
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
            perfil = os.path.basename(str(perfil))   # sem path traversal
            if not re.match(r'^[\w.\-]+$', perfil):
                return {'sucesso': False, 'erro': 'Perfil inválido'}
            if acao not in ('enforce', 'complain', 'disable'):
                return {'sucesso': False, 'erro': 'Ação inválida'}
            r = executar_comando(
                f'aa-{acao} /etc/apparmor.d/{perfil}', timeout=15
            )
            if r['sucesso']:
                return {'sucesso': True,
                        'mensagem': f'Perfil {perfil}: {acao}'}
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
                lambda m: m.group(0)[:-1] + f' {param}"', conteudo
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
            ).replace('apparmor=1 security=apparmor', '')
            with open(grub_file, 'w') as f:
                f.write(novo)
            executar_comando('update-grub 2>/dev/null', timeout=30)
        except Exception as e:
            logger.error(f"_remover_grub_apparmor: {e}")
