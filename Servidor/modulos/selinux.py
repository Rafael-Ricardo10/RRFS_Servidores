#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AppArmor (Debian) / SELinux - RRFS Servidores v2.3

v2.3:
  - CORRIGIDO (firewall parava): o módulo criava perfis PRÓPRIOS de
    AppArmor para /usr/sbin/ufw, iptables e tor e os colocava em
    enforce. O ufw é um script Python; o perfil não permitia nem ler
    /usr/sbin/ufw ("Permission denied"), nem as bibliotecas Python,
    xtables.lock etc. Agora o RRFS NÃO cria mais perfis para
    ufw/iptables/tor (o Debian já traz o system_tor) e remove
    automaticamente os perfis legados (ao iniciar e ao ativar).
  - Depois de ativar, o módulo testa 'ufw status'; se falhar, reverte
    sozinho o que for necessário e avisa.
  - 'Reinicie o servidor' só aparece quando o AppArmor realmente não
    está ativo no kernel em execução (antes dependia só do GRUB, que
    não existe em DietPi/SBC e fazia o aviso ficar para sempre).
  - Parâmetro de boot (apparmor=1 security=apparmor) também em
    /boot/cmdline.txt, /boot/firmware/cmdline.txt, dietpiEnv.txt e
    armbianEnv.txt (com backup .rrfs.bak), além do GRUB.
  - gerenciar_perfil: aceita o NOME real do perfil (ex.: /usr/sbin/ufw,
    docker-default); antes usava só o basename e falhava. Impede
    colocar ufw/iptables em enforce.
  - Lista de perfis sem o corte em 50; texto do status maior.
"""

import os
import re
import glob
import json
import shlex
import shutil
import logging

from modulos.utils import executar_comando

logger = logging.getLogger('RRFS.SELinux')

PARAM_AA = 'apparmor=1 security=apparmor'

PERFIL_OPENVPN_LEGADO = '/etc/apparmor.d/usr.sbin.openvpn.rrfs'

# perfis criados por versões antigas do RRFS (causavam o bloqueio)
PERFIS_LEGADOS_RRFS = [
    '/etc/apparmor.d/rrfs-ufw-iptables',
    '/etc/apparmor.d/usr.bin.tor.rrfs',
    PERFIL_OPENVPN_LEGADO,
]

# nunca colocar em enforce: quebram o firewall
PERFIS_CRITICOS = ('/usr/sbin/ufw', '/sbin/iptables', '/usr/sbin/iptables')

RE_PERFIL = re.compile(r'^[\w./{},+@:\-]{1,200}$')


class SELinuxManager:

    def __init__(self, base_dir):
        self.base_dir  = base_dir
        self._cfg_path = os.path.join(
            base_dir, 'dados', 'selinux_config.json'
        )
        self._config   = self._carregar()
        # corrige instalações que já foram afetadas
        self._limpar_perfis_legados()

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
    # LIMPEZA DE PERFIS LEGADOS
    # ══════════════════════════════════════════════════════

    def _limpar_perfis_legados(self):
        """Descarrega do kernel e apaga os perfis que o RRFS criava
        (ufw/iptables/tor/openvpn). Seguro rodar várias vezes."""
        removeu = False
        for caminho in PERFIS_LEGADOS_RRFS:
            try:
                if not os.path.exists(caminho):
                    continue
                executar_comando(
                    f'apparmor_parser -R {shlex.quote(caminho)} '
                    f'2>/dev/null', timeout=20
                )
                os.remove(caminho)
                removeu = True
                logger.error(f"selinux: perfil legado removido: {caminho}")
            except Exception as e:
                logger.error(f"_limpar_perfis_legados {caminho}: {e}")
        return removeu

    def _garantir_ufw_funcional(self):
        """Confirma que o ufw responde. Se um perfil estiver bloqueando,
        reverte. Retorna texto de aviso ('' se tudo certo)."""
        try:
            if not executar_comando('which ufw 2>/dev/null')['sucesso']:
                return ''
            r = executar_comando('ufw status', timeout=20)
            if r['sucesso'] and 'Permission denied' not in r.get('erro', ''):
                return ''
            logger.error(f"selinux: ufw não responde após ativar: "
                         f"{r.get('erro', '')}")
            self._limpar_perfis_legados()
            for nome in PERFIS_CRITICOS:
                executar_comando(
                    f'aa-complain {shlex.quote(nome)} 2>/dev/null',
                    timeout=15
                )
            r2 = executar_comando('ufw status', timeout=20)
            if r2['sucesso']:
                return (' O perfil que bloqueava o UFW foi removido '
                        'automaticamente.')
            return (' ATENÇÃO: o UFW ainda não responde; verifique '
                    '"ufw status" no terminal.')
        except Exception as e:
            logger.error(f"_garantir_ufw_funcional: {e}")
            return ''

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

    def _aa_ativo_no_kernel(self):
        """True se o AppArmor está habilitado no kernel EM EXECUÇÃO."""
        try:
            with open('/sys/module/apparmor/parameters/enabled') as f:
                if 'Y' in f.read():
                    return True
        except Exception:
            pass
        r = executar_comando('aa-status --enabled 2>/dev/null', timeout=10)
        return bool(r['sucesso'])

    def _boot_configurado(self):
        """True se algum arquivo de boot já tem o parâmetro."""
        for tipo, caminho in self._arquivos_boot():
            try:
                with open(caminho, 'r') as f:
                    txt = f.read()
                if 'apparmor=1' in txt and 'security=apparmor' in txt:
                    return True
            except Exception:
                pass
        return False

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

            kernel_aa = self._aa_ativo_no_kernel()
            modulo_carregado = 'apparmor module is loaded' in texto

            # só pede reinício se o kernel atual NÃO está com AppArmor
            precisa_reiniciar = not (kernel_aa or modulo_carregado)
            motivo = ''
            if precisa_reiniciar:
                motivo = ('Kernel em execução sem AppArmor. '
                          + ('Parâmetro de boot já configurado: '
                             'reinicie.' if self._boot_configurado()
                             else 'Ative o AppArmor para configurar o '
                                  'boot e depois reinicie.'))

            return {
                'motor':             'apparmor',
                'instalado':         True,
                'ativo':             ativo,
                'modo':              'enforce' if ativo else 'disabled',
                'perfis_enforce':    _n(r'(\d+) profiles? are in enforce mode'),
                'perfis_complain':   _n(r'(\d+) profiles? are in complain mode'),
                'processos':         _n(r'(\d+) processes? have profiles?'),
                'texto_completo':    texto[:4000],
                'perfis':            self._listar_perfis_aa(),
                'precisa_reiniciar': precisa_reiniciar,
                'motivo_reinicio':   motivo,
                'kernel_ativo':      kernel_aa,
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
                    perfis = [{'nome': n, 'modo': m}
                              for n, m in
                              dados.get('profiles', {}).items()]
                    ordem = {'enforce': 0, 'complain': 1}
                    perfis.sort(key=lambda p: (ordem.get(p['modo'], 2),
                                               p['nome']))
                    return perfis[:300]
                except Exception:
                    pass
            r2 = executar_comando(
                'ls /etc/apparmor.d/ 2>/dev/null | head -60'
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
                # 1) remove perfis próprios antigos ANTES de tudo
                self._limpar_perfis_legados()

                # 2) parâmetro de boot (GRUB / cmdline / dietpiEnv)
                self._configurar_boot_apparmor()

                executar_comando('systemctl enable apparmor', timeout=10)
                executar_comando('systemctl start apparmor', timeout=30)

                # 3) enforce seletivo só em perfis do próprio Debian
                self._aplicar_enforce_seguro()

                # 4) garante que o firewall continua funcionando
                aviso = self._garantir_ufw_funcional()

                self._config['ativo'] = True
                self._config['motor'] = 'apparmor'
                self._salvar()

                if self._aa_ativo_no_kernel():
                    msg = 'AppArmor ativado (perfis padrão do Debian).'
                else:
                    msg = ('AppArmor configurado. Reinicie o servidor '
                           'para ativar no kernel.')
                return {'sucesso': True, 'mensagem': msg + aviso}

            if motor == 'selinux':
                executar_comando('setenforce 1 2>/dev/null', timeout=10)
                self._config['ativo'] = True
                self._salvar()
                return {'sucesso': True,
                        'mensagem': 'SELinux ativado (enforce).'}

        except Exception as e:
            logger.error(f"selinux ativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def _aplicar_enforce_seguro(self):
        """enforce seletivo, somente em perfis que JÁ EXISTEM no
        sistema (Debian). Não cria perfis novos. Python/Flask (RRFS),
        NetworkManager e dhclient ficam em complain para não quebrar
        o painel. ufw/iptables nunca são tocados."""
        try:
            enforce = [
                '/etc/apparmor.d/usr.sbin.apache2',
                '/etc/apparmor.d/usr.sbin.nginx',
                '/etc/apparmor.d/usr.sbin.mysqld',
                '/etc/apparmor.d/usr.sbin.sshd',
                '/etc/apparmor.d/usr.bin.man',
                '/etc/apparmor.d/usr.sbin.rsyslogd',
            ]
            complain = [
                '/etc/apparmor.d/usr.bin.python3*',
                '/etc/apparmor.d/usr.sbin.NetworkManager',
                '/etc/apparmor.d/sbin.dhclient',
            ]
            for perfil in enforce:
                if os.path.exists(perfil):
                    executar_comando(
                        f'aa-enforce {shlex.quote(perfil)} 2>/dev/null',
                        timeout=10
                    )
            for perfil in complain:
                for p in glob.glob(perfil):
                    executar_comando(
                        f'aa-complain {shlex.quote(p)} 2>/dev/null',
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
                self._remover_boot_apparmor()
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
        """'perfil' é o NOME mostrado na lista (ex.: /usr/sbin/ufw,
        docker-default, system_tor)."""
        try:
            perfil = str(perfil or '').strip()
            if (not RE_PERFIL.match(perfil) or '..' in perfil):
                return {'sucesso': False, 'erro': 'Perfil inválido'}
            if acao not in ('enforce', 'complain', 'disable'):
                return {'sucesso': False, 'erro': 'Ação inválida'}
            if '//' in perfil:
                return {'sucesso': False,
                        'erro': ('Perfil filho: gerencie o perfil '
                                 'principal.')}
            if perfil in PERFIS_CRITICOS and acao == 'enforce':
                return {'sucesso': False,
                        'erro': ('Não recomendado: enforce em '
                                 f'{perfil} pode quebrar o firewall.')}

            cmd = {'enforce': 'aa-enforce', 'complain': 'aa-complain',
                   'disable': 'aa-disable'}[acao]
            tentativas = [perfil]
            if not perfil.startswith('/'):
                tentativas.append(
                    f'/etc/apparmor.d/{os.path.basename(perfil)}'
                )
            ultimo = ''
            for alvo in tentativas:
                r = executar_comando(f'{cmd} {shlex.quote(alvo)}',
                                     timeout=20)
                if r['sucesso']:
                    return {'sucesso': True,
                            'mensagem': f'Perfil {perfil}: {acao}'}
                ultimo = (r.get('erro') or r.get('saida') or '')[:200]
            return {'sucesso': False,
                    'erro': f'Falha ao aplicar {acao}: {ultimo}'.strip()}
        except Exception as e:
            logger.error(f"selinux gerenciar_perfil: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # PARÂMETRO DE BOOT (GRUB, Raspberry/DietPi, Armbian)
    # ══════════════════════════════════════════════════════

    def _arquivos_boot(self):
        """[(tipo, caminho)] de arquivos de boot existentes."""
        achados, vistos = [], set()

        def add(tipo, caminho):
            if not os.path.exists(caminho):
                return
            real = os.path.realpath(caminho)
            if real in vistos:
                return
            vistos.add(real)
            achados.append((tipo, caminho))

        add('grub', '/etc/default/grub')
        add('cmdline', '/boot/firmware/cmdline.txt')
        add('cmdline', '/boot/cmdline.txt')
        add('env', '/boot/dietpiEnv.txt')
        add('env', '/boot/armbianEnv.txt')
        return achados

    def _backup_boot(self, caminho):
        bkp = caminho + '.rrfs.bak'
        try:
            if not os.path.exists(bkp):
                shutil.copy2(caminho, bkp)
        except Exception as e:
            logger.error(f"backup {caminho}: {e}")

    def _configurar_boot_apparmor(self):
        for tipo, caminho in self._arquivos_boot():
            try:
                with open(caminho, 'r') as f:
                    conteudo = f.read()
                if 'apparmor=1' in conteudo and \
                        'security=apparmor' in conteudo:
                    continue
                self._backup_boot(caminho)

                if tipo == 'grub':
                    novo = re.sub(
                        r'(GRUB_CMDLINE_LINUX="[^"]*)"',
                        lambda m: m.group(0)[:-1] + f' {PARAM_AA}"',
                        conteudo
                    )
                    if novo == conteudo:
                        novo += f'\nGRUB_CMDLINE_LINUX="{PARAM_AA}"\n'
                    with open(caminho, 'w') as f:
                        f.write(novo)
                    executar_comando('update-grub 2>/dev/null',
                                     timeout=60)

                elif tipo == 'cmdline':
                    # cmdline.txt precisa ser UMA única linha
                    linha = ' '.join(l.strip() for l in
                                     conteudo.splitlines() if l.strip())
                    with open(caminho, 'w') as f:
                        f.write(f'{linha} {PARAM_AA}\n')

                elif tipo == 'env':
                    linhas = conteudo.splitlines()
                    achou = False
                    for i, l in enumerate(linhas):
                        if l.startswith('extraargs='):
                            linhas[i] = l.rstrip() + f' {PARAM_AA}'
                            achou = True
                            break
                    if not achou:
                        linhas.append(f'extraargs={PARAM_AA}')
                    with open(caminho, 'w') as f:
                        f.write('\n'.join(linhas) + '\n')
            except Exception as e:
                logger.error(f"_configurar_boot_apparmor {caminho}: {e}")

    def _remover_boot_apparmor(self):
        for tipo, caminho in self._arquivos_boot():
            try:
                with open(caminho, 'r') as f:
                    conteudo = f.read()
                if PARAM_AA not in conteudo:
                    continue
                self._backup_boot(caminho)
                novo = conteudo.replace(f' {PARAM_AA}', '') \
                               .replace(PARAM_AA, '')
                with open(caminho, 'w') as f:
                    f.write(novo)
                if tipo == 'grub':
                    executar_comando('update-grub 2>/dev/null',
                                     timeout=60)
            except Exception as e:
                logger.error(f"_remover_boot_apparmor {caminho}: {e}")
