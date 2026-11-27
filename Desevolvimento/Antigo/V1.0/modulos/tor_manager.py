#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tor Hidden Services Manager - RRFS Servidores
"""

import os
import re
import json
import time
import shutil
import logging
import hashlib
from datetime import datetime

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.Tor')


class TorManager:

    def __init__(self, base_dir):
        self.base_dir          = base_dir
        self.config_path       = os.path.join(
            base_dir, 'dados', 'tor_config.json'
        )
        self.torrc_path        = '/etc/tor/torrc'
        self.hs_dir            = '/var/lib/tor'
        self.config            = self._carregar()
        self._firewall_ufw     = None

    def set_firewall_ufw(self, fw):
        self._firewall_ufw = fw

    # ── config ────────────────────────────────────────────

    def _carregar(self):
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
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
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2,
                          ensure_ascii=False)
        except Exception as e:
            logger.error(f"tor salvar: {e}")

    def _gerar_id(self):
        raw = f"{datetime.now().isoformat()}{os.urandom(16).hex()}"
        return 'hs_' + hashlib.sha256(
            raw.encode()
        ).hexdigest()[:12]

    # ── status ────────────────────────────────────────────

    def obter_status(self):
        try:
            instalado   = self._instalado()
            ativo       = False
            if instalado:
                r = executar_comando(
                    'systemctl is-active tor 2>/dev/null'
                )
                ativo = (r['sucesso'] and
                         'active' in r.get('saida', ''))
            servicos = self._servicos_com_onion()
            return {
                'instalado': instalado,
                'servico_ativo': ativo,
                'ativo': self.config.get('ativo', False),
                'servicos': servicos,
                'total': len(servicos)
            }
        except Exception as e:
            logger.error(f"tor obter_status: {e}")
            return {'instalado': False, 'servico_ativo': False,
                    'ativo': False, 'servicos': [], 'total': 0}

    def _instalado(self):
        r = executar_comando('which tor 2>/dev/null')
        return r['sucesso']

    def _servicos_com_onion(self):
        result = []
        for s in self.config.get('servicos', []):
            sc = dict(s)
            sc['onion'] = self._ler_onion(s.get('dir_id', ''))
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
                    return f.read().strip()
        except PermissionError:
            r = executar_comando(f'cat {path} 2>/dev/null')
            if r['sucesso']:
                return r['saida'].strip()
        except Exception as e:
            logger.error(f"ler_onion: {e}")
        return ''

    # ── ativar / desativar ────────────────────────────────

    def ativar(self):
        try:
            if not self._instalado():
                r = executar_comando(
                    'apt-get install -y tor', timeout=180
                )
                if not r['sucesso']:
                    return {'sucesso': False,
                            'erro': 'Falha ao instalar Tor'}
            self._gerar_torrc()
            executar_comando('systemctl enable tor', timeout=30)
            r = executar_comando(
                'systemctl restart tor', timeout=30
            )
            if not r['sucesso']:
                return {'sucesso': False,
                        'erro': f"Falha: {r.get('erro','')}"}
            time.sleep(8)
            self.config['ativo'] = True
            self._salvar()
            return {'sucesso': True,
                    'mensagem': 'Tor ativado com sucesso!'}
        except Exception as e:
            logger.error(f"tor ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def desativar(self):
        try:
            executar_comando('systemctl stop tor', timeout=30)
            executar_comando('systemctl disable tor', timeout=30)
            self.config['ativo'] = False
            self._salvar()
            return {'sucesso': True, 'mensagem': 'Tor desativado'}
        except Exception as e:
            logger.error(f"tor desativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── adicionar serviço ─────────────────────────────────

    def adicionar_servico(self, nome, porta_virtual,
                          porta_destino, interface='localhost'):
        try:
            porta_virtual  = int(porta_virtual)
            porta_destino  = int(porta_destino)

            if not nome or not nome.strip():
                return {'sucesso': False, 'erro': 'Nome obrigatório'}
            nome = nome.strip()

            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    return {'sucesso': False,
                            'erro': f'Serviço "{nome}" já existe'}

            ip_destino = self._ip_interface(interface)
            dir_id     = self._gerar_id()

            servico = {
                'nome': nome,
                'dir_id': dir_id,
                'porta_virtual': porta_virtual,
                'porta_destino': porta_destino,
                'interface': interface,
                'ip_destino': ip_destino,
                'pausado': False,
                'criado_em': datetime.now().isoformat()
            }
            self.config.setdefault('servicos', []).append(servico)
            self._salvar()

            # regra UFW automática
            self._criar_regra_ufw(nome, porta_destino,
                                  interface, ip_destino)

            onion = ''
            if self.config.get('ativo'):
                self._gerar_torrc()
                executar_comando(
                    'systemctl restart tor', timeout=30
                )
                time.sleep(8)
                onion = self._ler_onion(dir_id)

            return {
                'sucesso': True,
                'mensagem': f'Serviço "{nome}" adicionado!',
                'onion': onion or '(ative o Tor para gerar)'
            }
        except ValueError:
            return {'sucesso': False, 'erro': 'Portas inválidas'}
        except Exception as e:
            logger.error(f"adicionar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── editar serviço ────────────────────────────────────

    def editar_servico(self, nome_orig, nome_novo,
                       porta_virtual, porta_destino,
                       interface='localhost'):
        try:
            porta_virtual = int(porta_virtual)
            porta_destino = int(porta_destino)
            nome_novo     = nome_novo.strip()

            idx = None
            srv = None
            for i, s in enumerate(
                self.config.get('servicos', [])
            ):
                if s.get('nome') == nome_orig:
                    idx = i
                    srv = s
                    break

            if srv is None:
                return {'sucesso': False,
                        'erro': f'"{nome_orig}" não encontrado'}

            ip_destino = self._ip_interface(interface)
            dir_id     = srv.get('dir_id', '')

            self.config['servicos'][idx] = {
                'nome': nome_novo,
                'dir_id': dir_id,
                'porta_virtual': porta_virtual,
                'porta_destino': porta_destino,
                'interface': interface,
                'ip_destino': ip_destino,
                'pausado': srv.get('pausado', False),
                'criado_em': srv.get('criado_em', ''),
                'editado_em': datetime.now().isoformat()
            }
            self._salvar()

            # atualizar UFW
            self._remover_regra_ufw(nome_orig)
            self._criar_regra_ufw(
                nome_novo, porta_destino, interface, ip_destino
            )

            if self.config.get('ativo'):
                self._gerar_torrc()
                executar_comando(
                    'systemctl restart tor', timeout=30
                )

            return {'sucesso': True,
                    'mensagem': f'Serviço "{nome_novo}" editado!'}
        except ValueError:
            return {'sucesso': False, 'erro': 'Portas inválidas'}
        except Exception as e:
            logger.error(f"editar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── pausar / remover serviço ──────────────────────────

    def pausar_servico(self, nome):
        try:
            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    s['pausado'] = not s.get('pausado', False)
                    self._salvar()
                    self._gerar_torrc()
                    if self.config.get('ativo'):
                        executar_comando(
                            'systemctl restart tor', timeout=30
                        )
                    estado = 'pausado' if s['pausado'] \
                        else 'reativado'
                    return {'sucesso': True,
                            'mensagem': f'Serviço {estado}'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"pausar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_servico(self, nome):
        try:
            servicos = self.config.get('servicos', [])
            encontrado = None
            for i, s in enumerate(servicos):
                if s.get('nome') == nome:
                    encontrado = servicos.pop(i)
                    break

            if not encontrado:
                return {'sucesso': False, 'erro': 'Não encontrado'}

            self.config['servicos'] = servicos
            self._salvar()

            # remover UFW
            self._remover_regra_ufw(nome)

            # remover diretório
            dir_id  = encontrado.get('dir_id', '')
            hs_path = os.path.join(
                self.hs_dir, f'hidden_service_{dir_id}'
            )
            if os.path.exists(hs_path):
                shutil.rmtree(hs_path, ignore_errors=True)

            if self.config.get('ativo'):
                self._gerar_torrc()
                executar_comando(
                    'systemctl restart tor', timeout=30
                )

            return {'sucesso': True,
                    'mensagem': f'Serviço "{nome}" removido'}
        except Exception as e:
            logger.error(f"remover_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── renovar onion ─────────────────────────────────────

    def renovar_onion(self, nome):
        try:
            for i, s in enumerate(
                self.config.get('servicos', [])
            ):
                if s.get('nome') == nome:
                    dir_id_antigo = s.get('dir_id', '')
                    hs_path = os.path.join(
                        self.hs_dir,
                        f'hidden_service_{dir_id_antigo}'
                    )
                    if os.path.exists(hs_path):
                        shutil.rmtree(hs_path,
                                      ignore_errors=True)
                    novo_id = self._gerar_id()
                    self.config['servicos'][i]['dir_id'] = novo_id
                    self._salvar()
                    if self.config.get('ativo'):
                        self._gerar_torrc()
                        executar_comando(
                            'systemctl restart tor', timeout=30
                        )
                        time.sleep(10)
                        onion = self._ler_onion(novo_id)
                        return {
                            'sucesso': True,
                            'mensagem': 'Endereço renovado!',
                            'onion': onion
                        }
                    return {'sucesso': True,
                            'mensagem': 'Chaves removidas. '
                            'Ative o Tor para gerar novo endereço.'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"renovar_onion: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def obter_onion(self, nome):
        try:
            for s in self.config.get('servicos', []):
                if s.get('nome') == nome:
                    onion = self._ler_onion(s.get('dir_id', ''))
                    return {'sucesso': True, 'onion': onion,
                            'nome': nome}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"obter_onion: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── torrc ─────────────────────────────────────────────

    def _gerar_torrc(self):
        try:
            if os.path.exists(self.torrc_path):
                bkp = f'{self.torrc_path}.rrfs.bak'
                if not os.path.exists(bkp):
                    shutil.copy2(self.torrc_path, bkp)

            linhas = []
            if os.path.exists(self.torrc_path):
                em_bloco = False
                with open(self.torrc_path, 'r') as f:
                    for linha in f:
                        if '# === RRFS HIDDEN SERVICES ===' \
                                in linha:
                            em_bloco = True
                            continue
                        if '# === FIM RRFS ===' in linha:
                            em_bloco = False
                            continue
                        if not em_bloco:
                            linhas.append(linha)

            linhas.append('\n')
            linhas.append('# === RRFS HIDDEN SERVICES ===\n')
            linhas.append(
                f'# {datetime.now().isoformat()}\n'
            )
            linhas.append('\n')

            for s in self.config.get('servicos', []):
                if s.get('pausado', False):
                    continue
                dir_id = s.get('dir_id', '')
                hs_path = os.path.join(
                    self.hs_dir,
                    f'hidden_service_{dir_id}'
                )
                pv = s.get('porta_virtual', 80)
                pd = s.get('porta_destino', 80)
                ip = s.get('ip_destino', '127.0.0.1')
                linhas.append(f'# {s.get("nome","")}\n')
                linhas.append(f'HiddenServiceDir {hs_path}\n')
                linhas.append(
                    f'HiddenServicePort {pv} {ip}:{pd}\n'
                )
                linhas.append('\n')

            linhas.append('# === FIM RRFS ===\n')

            with open(self.torrc_path, 'w') as f:
                f.writelines(linhas)

            executar_comando(
                f'chown debian-tor:debian-tor {self.torrc_path}'
            )
            executar_comando(f'chmod 644 {self.torrc_path}')
        except Exception as e:
            logger.error(f"gerar_torrc: {e}")

    # ── UFW integração ────────────────────────────────────

    def _criar_regra_ufw(self, nome, porta, interface, ip):
        if not self._firewall_ufw:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            dados = {
                'nome': f'Tor:{nome}',
                'interface': 'lo' if (
                    not interface or interface == 'localhost'
                ) else interface,
                'direcao': 'in',
                'protocolo': 'tcp',
                'ip': '127.0.0.0/8' if (
                    not interface or interface == 'localhost'
                ) else '',
                'porta': str(porta)
            }
            self._firewall_ufw.adicionar_regra_automatica(
                f'Tor:{nome}', dados,
                FirewallUFW.CAT_TOR
            )
        except Exception as e:
            logger.error(f"criar_regra_ufw tor: {e}")

    def _remover_regra_ufw(self, nome):
        if not self._firewall_ufw:
            return
        try:
            self._firewall_ufw.remover_regras_tor(f'Tor:{nome}')
        except Exception as e:
            logger.error(f"remover_regra_ufw tor: {e}")

    # ── helpers ───────────────────────────────────────────

    def _ip_interface(self, interface):
        if not interface or interface == 'localhost':
            return '127.0.0.1'
        r = executar_comando(
            f"ip -4 addr show {interface} 2>/dev/null | "
            f"grep 'inet ' | awk '{{print $2}}' | "
            f"cut -d/ -f1 | head -1"
        )
        return r['saida'].strip() if r['sucesso'] \
            else '127.0.0.1'
