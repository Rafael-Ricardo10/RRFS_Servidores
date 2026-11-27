#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AppArmor (Debian) / SELinux - RRFS Servidores v2.0

No Debian, AppArmor é o sistema padrão e nativo.
SELinux existe mas requer configuração extensa.
O RRFS usa AppArmor por padrão no Debian.
"""

import os
import re
import json
import logging
from datetime import datetime

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.SELinux')


class SELinuxManager:
    """
    Gerencia AppArmor no Debian (sistema nativo).
    Interface chamada de 'selinux' para simplicidade,
    mas implementa AppArmor que é o padrão Debian.
    """

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
                os.path.dirname(self._cfg_path),
                exist_ok=True
            )
            with open(self._cfg_path, 'w') as f:
                json.dump(self._config, f,
                          indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"selinux salvar: {e}")

    # ── detectar motor ────────────────────────────────────

    def _detectar_motor(self):
        """
        No Debian: AppArmor é padrão e recomendado.
        SELinux também disponível mas menos integrado.
        """
        # verificar AppArmor
        r = executar_comando('which apparmor_status 2>/dev/null')
        if r['sucesso']:
            return 'apparmor'

        r = executar_comando(
            'dpkg -l apparmor 2>/dev/null | grep "^ii"'
        )
        if r['sucesso']:
            return 'apparmor'

        # verificar SELinux
        r = executar_comando('which sestatus 2>/dev/null')
        if r['sucesso']:
            return 'selinux'

        return 'nenhum'

    # ── status ────────────────────────────────────────────

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
                    'mensagem':  'AppArmor não instalado. '
                                 'Use "Ativar" para instalar.',
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
            ativo = (r['sucesso'] and
                    'active' in r.get('saida', ''))

            r2 = executar_comando(
                'apparmor_status 2>/dev/null || '
                'aa-status 2>/dev/null',
                timeout=10
            )
            texto = r2.get('saida', '')

            perfis_enforce  = 0
            perfis_complain = 0
            processos       = 0

            m = re.search(
                r'(\d+) profiles? are in enforce mode', texto
            )
            if m:
                perfis_enforce = int(m.group(1))

            m = re.search(
                r'(\d+) profiles? are in complain mode', texto
            )
            if m:
                perfis_complain = int(m.group(1))

            m = re.search(
                r'(\d+) processes? have profiles?', texto
            )
            if m:
                processos = int(m.group(1))

            # verificar se GRUB já tem os parâmetros AppArmor
            # se tiver, não precisa reiniciar
            grub_ok = False
            try:
                with open('/etc/default/grub', 'r') as f:
                    grub_content = f.read()
                grub_ok = 'apparmor=1' in grub_content
            except Exception:
                pass

            # verificar se kernel atual tem AppArmor ativo
            r3 = executar_comando(
                'cat /sys/module/apparmor/parameters/enabled '
                '2>/dev/null'
            )
            kernel_aa = (r3['sucesso'] and
                        'Y' in r3.get('saida', ''))

            # se AppArmor está ativo no kernel, não precisa reiniciar
            precisa_reiniciar = (
                not kernel_aa and not grub_ok
            )

            return {
                'motor':              'apparmor',
                'instalado':          True,
                'ativo':              ativo,
                'modo':               'enforce' if ativo
                                    else 'disabled',
                'perfis_enforce':     perfis_enforce,
                'perfis_complain':    perfis_complain,
                'processos':          processos,
                'texto_completo':     texto[:500],
                'perfis':             self._listar_perfis_aa(),
                # NOVO: só mostrar aviso se realmente precisar
                'precisa_reiniciar':  precisa_reiniciar,
            }
        except Exception as e:
            logger.error(f"_status_apparmor: {e}")
            return {'motor': 'apparmor', 'ativo': False}

    def _status_selinux(self):
        try:
            r = executar_comando('sestatus 2>/dev/null', timeout=10)
            texto = r.get('saida', '')
            ativo = 'enabled' in texto.lower()
            modo  = 'enforcing'
            m = re.search(r'Current mode:\s*(\w+)', texto)
            if m:
                modo = m.group(1)
            return {
                'motor':        'selinux',
                'instalado':    True,
                'ativo':        ativo,
                'modo':         modo,
                'texto_completo': texto,
                'perfis':       []
            }
        except Exception as e:
            logger.error(f"_status_selinux: {e}")
            return {'motor': 'selinux', 'ativo': False}

    def _listar_perfis_aa(self):
        """Listar perfis AppArmor"""
        try:
            r = executar_comando(
                'aa-status --json 2>/dev/null', timeout=10
            )
            if r['sucesso'] and r['saida']:
                try:
                    dados = json.loads(r['saida'])
                    perfis = []
                    for nome, modo in dados.get(
                        'profiles', {}
                    ).items():
                        perfis.append({
                            'nome': nome,
                            'modo': modo
                        })
                    return perfis[:50]
                except Exception:
                    pass

            # fallback: parsear texto
            r2 = executar_comando(
                'ls /etc/apparmor.d/ 2>/dev/null | head -30'
            )
            perfis = []
            if r2['sucesso']:
                for p in r2['saida'].splitlines():
                    p = p.strip()
                    if p and not p.startswith('#'):
                        perfis.append({
                            'nome': p,
                            'modo': 'enforce'
                        })
            return perfis
        except Exception as e:
            logger.error(f"_listar_perfis_aa: {e}")
            return []

    # ── ativar ────────────────────────────────────────────

    def ativar(self):
        try:
            motor = self._detectar_motor()

            if motor == 'nenhum':
                # instalar AppArmor no Debian
                r = executar_comando(
                    'apt-get install -y '
                    'apparmor apparmor-utils '
                    'apparmor-profiles apparmor-profiles-extra',
                    timeout=300
                )
                if not r['sucesso']:
                    return {
                        'sucesso': False,
                        'erro': 'Falha ao instalar AppArmor'
                    }

            if motor in ('apparmor', 'nenhum'):
                # habilitar AppArmor no boot (GRUB)
                self._configurar_grub_apparmor()

                # iniciar serviço
                executar_comando(
                    'systemctl enable apparmor', timeout=10
                )
                r = executar_comando(
                    'systemctl start apparmor', timeout=30
                )

                # colocar todos perfis em enforce
                executar_comando(
                    'aa-enforce /etc/apparmor.d/* 2>/dev/null',
                    timeout=30
                )

                self._config['ativo'] = True
                self._config['motor'] = 'apparmor'
                self._salvar()

                return {
                    'sucesso': True,
                    'mensagem': (
                        'AppArmor ativado! '
                        'Todos os perfis em modo enforce. '
                        'Reinicie o servidor para efeito completo.'
                    )
                }

            elif motor == 'selinux':
                r = executar_comando(
                    'setenforce 1 2>/dev/null', timeout=10
                )
                self._config['ativo'] = True
                self._salvar()
                return {
                    'sucesso': True,
                    'mensagem': 'SELinux ativado (enforce).'
                }

        except Exception as e:
            logger.error(f"selinux ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── desativar ─────────────────────────────────────────

    def desativar(self):
        try:
            motor = self._detectar_motor()

            if motor == 'apparmor':
                executar_comando(
                    'systemctl stop apparmor', timeout=15
                )
                executar_comando(
                    'aa-teardown 2>/dev/null', timeout=15
                )
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
                r = executar_comando(
                    'setenforce 0 2>/dev/null', timeout=10
                )
                self._config['ativo'] = False
                self._salvar()
                return {
                    'sucesso': True,
                    'mensagem': 'SELinux em modo permissivo.'
                }

            return {
                'sucesso': False,
                'erro': 'Nenhum motor encontrado'
            }
        except Exception as e:
            logger.error(f"selinux desativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── gerenciar perfis ──────────────────────────────────

    def listar_perfis(self):
        return self._listar_perfis_aa()

    def gerenciar_perfil(self, perfil, acao):
        """
        acao: enforce, complain, disable
        """
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
                return {
                    'sucesso': True,
                    'mensagem': f'Perfil {perfil}: {acao}'
                }
            return {
                'sucesso': False,
                'erro': r.get('erro', 'Falha')
            }
        except Exception as e:
            logger.error(f"selinux gerenciar_perfil: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── GRUB ──────────────────────────────────────────────

    def _configurar_grub_apparmor(self):
        """Adicionar parâmetros AppArmor ao GRUB"""
        try:
            grub_file = '/etc/default/grub'
            if not os.path.exists(grub_file):
                return

            with open(grub_file, 'r') as f:
                conteudo = f.read()

            param = 'apparmor=1 security=apparmor'

            # já tem parâmetro?
            if param in conteudo:
                return

            # adicionar ao GRUB_CMDLINE_LINUX
            novo = re.sub(
                r'(GRUB_CMDLINE_LINUX="[^"]*)"',
                lambda m: m.group(0)[:-1] +
                f' {param}"',
                conteudo
            )

            if novo == conteudo:
                # fallback: adicionar nova linha
                novo += f'\nGRUB_CMDLINE_LINUX="{param}"\n'

            with open(grub_file, 'w') as f:
                f.write(novo)

            executar_comando('update-grub 2>/dev/null', timeout=30)

        except Exception as e:
            logger.error(f"_configurar_grub_apparmor: {e}")

    def _remover_grub_apparmor(self):
        """Remover parâmetros AppArmor do GRUB"""
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
