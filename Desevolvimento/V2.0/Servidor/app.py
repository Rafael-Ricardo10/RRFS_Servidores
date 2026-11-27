#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RRFS Servidores v2.5
v2.5:
  - Removido o módulo conexao (WAN/WiFi/VPN)
  - Novo módulo Tox (acesso remoto via protocolo Tox)
  - Login: sem injeção de comando via senha, bloqueio por tentativas,
    cookies de sessão seguros
  - IP público em cache (antes fazia curl a cada atualização do painel)
  - Decorator @tratar_erros substitui os try/except repetidos
"""

import os
import sys
import ssl
import time
import hmac
import logging
import threading
import subprocess
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file, after_this_request
)

# ── paths ──────────────────────────────────────────────────
BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
DADOS_DIR = os.path.join(BASE_DIR, 'dados')
SSL_DIR   = os.path.join(DADOS_DIR, 'ssl')
LOGS_DIR  = os.path.join(DADOS_DIR, 'logs')

for d in [DADOS_DIR, SSL_DIR, LOGS_DIR]:
    os.makedirs(d, exist_ok=True)

# ══════════════════════════════════════════════════════════
# LOGGING - APENAS ERROS REAIS
# ══════════════════════════════════════════════════════════

LOG_FILE = os.path.join(LOGS_DIR, 'erros.log')

_file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
_file_handler.setLevel(logging.ERROR)
_file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    datefmt='%d/%m/%Y %H:%M:%S'
))

for _nome in ['werkzeug', 'werkzeug.serving', 'werkzeug.routing',
              'flask', 'flask.app', 'urllib3',
              'urllib3.connectionpool', 'requests',
              'charset_normalizer', 'paramiko', 'paramiko.transport']:
    _lg = logging.getLogger(_nome)
    _lg.setLevel(logging.CRITICAL + 1)
    _lg.propagate = False
    _lg.handlers  = []

_root = logging.getLogger()
_root.setLevel(logging.ERROR)
_root.handlers = []
_root.addHandler(_file_handler)

logger = logging.getLogger('RRFS')
logger.setLevel(logging.ERROR)
logger.propagate = True

# ── módulos ────────────────────────────────────────────────
sys.path.insert(0, BASE_DIR)
from modulos.utils        import executar_comando, gerar_ssl
from modulos.firewall_ufw import FirewallUFW
from modulos.tor_manager  import TorManager
from modulos.tox_remoto   import ToxManager
from modulos.dns_seguro   import DNSSeguro
from modulos.antivirus    import AntivirusManager
from modulos.selinux      import SELinuxManager

# ── Flask ──────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32)
app.permanent_session_lifetime = timedelta(hours=8)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Strict',
)

app.logger.handlers  = []
app.logger.propagate = False
app.logger.setLevel(logging.CRITICAL + 1)
logging.getLogger('werkzeug').disabled = True

# ── instâncias ─────────────────────────────────────────────
firewall  = FirewallUFW(BASE_DIR)
tor       = TorManager(BASE_DIR)
tox       = ToxManager(BASE_DIR)
dns       = DNSSeguro(BASE_DIR)
antivirus = AntivirusManager(BASE_DIR)
selinux   = SELinuxManager(BASE_DIR)

tor.set_firewall_ufw(firewall)
tox.set_firewall(firewall)
dns.set_firewall(firewall)

# ══════════════════════════════════════════════════════════
# SSL
# ══════════════════════════════════════════════════════════

def garantir_ssl():
    cert = os.path.join(SSL_DIR, 'cert.pem')
    key  = os.path.join(SSL_DIR, 'key.pem')
    if not os.path.exists(cert) or not os.path.exists(key):
        gerar_ssl(SSL_DIR)
    return cert, key

# ══════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════

_tentativas = {}               # ip -> [contagem, inicio_janela]
_tent_lock  = threading.Lock()
MAX_TENTATIVAS = 5
JANELA_BLOQUEIO = 15 * 60


def _bloqueado(ip):
    with _tent_lock:
        reg = _tentativas.get(ip)
        if not reg:
            return 0
        if time.time() - reg[1] > JANELA_BLOQUEIO:
            _tentativas.pop(ip, None)
            return 0
        if reg[0] >= MAX_TENTATIVAS:
            return int(JANELA_BLOQUEIO - (time.time() - reg[1]))
    return 0


def _registrar_falha(ip):
    with _tent_lock:
        reg = _tentativas.get(ip)
        if not reg or time.time() - reg[1] > JANELA_BLOQUEIO:
            _tentativas[ip] = [1, time.time()]
        else:
            reg[0] += 1


def verificar_senha_root(senha):
    """
    A senha NUNCA é interpolada em comando/código.
    1) python-pam em processo; 2) python-pam em subprocesso via stdin;
    3) /etc/shadow (spwd/crypt, Python < 3.13).
    """
    if not senha or len(senha) > 256:
        return False
    try:
        try:
            import pam
            return bool(pam.pam().authenticate('root', senha))
        except ImportError:
            pass

        try:
            import spwd
            import crypt
            h = spwd.getspnam('root').sp_pwdp
            if h and not h.startswith(('!', '*')):
                return hmac.compare_digest(crypt.crypt(senha, h), h)
        except (ImportError, KeyError, PermissionError):
            pass
        except Exception as e:
            logger.error(f"verificar_senha_root shadow: {e}")

        proc = subprocess.run(
            ['python3', '-c',
             'import sys,pam;s=sys.stdin.read();'
             'sys.exit(0 if pam.pam().authenticate("root",s) else 1)'],
            input=senha, capture_output=True, text=True, timeout=10
        )
        return proc.returncode == 0
    except Exception as e:
        logger.error(f"verificar_senha_root: {e}")
    return False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logado'):
            if request.path.startswith('/api/'):
                return jsonify({'sucesso': False,
                                'erro': 'Não autenticado'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def tratar_erros(f):
    """Captura exceções, registra no log e devolve JSON padrão."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"{f.__name__}: {e}")
            return jsonify({'sucesso': False, 'erro': str(e)})
    return decorated


def _json():
    return request.get_json(silent=True) or {}

# ══════════════════════════════════════════════════════════
# LOGIN
# ══════════════════════════════════════════════════════════

@app.route('/', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        ip = request.remote_addr or '?'
        espera = _bloqueado(ip)
        if espera:
            erro = f'Muitas tentativas. Aguarde {espera // 60 + 1} min.'
        elif verificar_senha_root(request.form.get('senha', '')):
            with _tent_lock:
                _tentativas.pop(ip, None)
            session.clear()
            session.permanent = True
            session['logado'] = True
            session['login_em'] = datetime.now().isoformat()
            return redirect(url_for('dashboard'))
        else:
            _registrar_falha(ip)
            erro = 'Senha incorreta'
            logger.error(f"Login falhou - IP: {ip}")
    return render_template('login.html', erro=erro)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ══════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════

_ip_cache = {'valor': 'N/A', 'ts': 0}


def _obter_ip_publico():
    if time.time() - _ip_cache['ts'] < 120:
        return _ip_cache['valor']
    try:
        r = executar_comando(
            'curl -s --max-time 5 https://api.ipify.org', timeout=8
        )
        _ip_cache['valor'] = (r['saida'].strip()
                              if r['sucesso'] and r['saida'] else 'N/A')
    except Exception as e:
        logger.error(f"_obter_ip_publico: {e}")
        _ip_cache['valor'] = 'N/A'
    _ip_cache['ts'] = time.time()
    return _ip_cache['valor']


def _info_sistema():
    try:
        uptime = executar_comando('uptime -p')
        mem    = executar_comando(
            "free -h | grep Mem | awk '{print $3\"/\"$2}'")
        cpu    = executar_comando(
            "top -bn1 | grep 'Cpu' | awk '{print $2}'")
        disk   = executar_comando(
            "df -h / | tail -1 | awk '{print $3\"/\"$2}'")
        return {
            'uptime':  uptime.get('saida', 'N/A'),
            'memoria': mem.get('saida', 'N/A'),
            'cpu':     cpu.get('saida', 'N/A') + '%',
            'disco':   disk.get('saida', 'N/A'),
        }
    except Exception as e:
        logger.error(f"_info_sistema: {e}")
        return {}


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/status_geral')
@login_required
@tratar_erros
def api_status_geral():
    return jsonify({
        'sucesso':      True,
        'ufw':          firewall.obter_status(),
        'tor':          tor.obter_status(),
        'tox':          tox.obter_status_resumido(),
        'dns':          dns.obter_status_resumido(),
        'antivirus':    antivirus.obter_status_resumido(),
        'selinux':      selinux.obter_status(),
        'regras_count': len(firewall.listar_regras_salvas()),
        'ip_publico':   _obter_ip_publico(),
        'sistema':      _info_sistema(),
        'timestamp':    datetime.now().strftime('%d/%m/%Y %H:%M:%S')
    })

# ══════════════════════════════════════════════════════════
# FIREWALL
# ══════════════════════════════════════════════════════════

@app.route('/firewall')
@login_required
def pagina_firewall():
    return render_template('firewall.html')

@app.route('/api/firewall/status')
@login_required
@tratar_erros
def api_firewall_status():
    return jsonify({
        'sucesso':    True,
        'status':     firewall.obter_status(),
        'regras':     firewall.listar_regras_salvas(),
        'interfaces': firewall.obter_interfaces_disponiveis()
    })

@app.route('/api/firewall/adicionar', methods=['POST'])
@login_required
@tratar_erros
def api_firewall_adicionar():
    return jsonify(firewall.adicionar_regra(_json()))

@app.route('/api/firewall/remover', methods=['POST'])
@login_required
@tratar_erros
def api_firewall_remover():
    return jsonify(firewall.remover_regra(_json().get('indice')))

@app.route('/api/firewall/pausar', methods=['POST'])
@login_required
@tratar_erros
def api_firewall_pausar():
    return jsonify(firewall.pausar_regra(_json().get('indice')))

@app.route('/api/firewall/reativar', methods=['POST'])
@login_required
@tratar_erros
def api_firewall_reativar():
    return jsonify(firewall.reativar_regra(_json().get('indice')))

@app.route('/api/firewall/editar', methods=['POST'])
@login_required
@tratar_erros
def api_firewall_editar():
    return jsonify(firewall.editar_regra(_json()))

@app.route('/api/firewall/config_interface', methods=['POST'])
@login_required
@tratar_erros
def api_config_interface():
    return jsonify(
        firewall.iniciar_mudanca_interface(_json().get('interface', ''))
    )

@app.route('/api/firewall/confirmar_interface', methods=['POST'])
@login_required
@tratar_erros
def api_confirmar_interface():
    return jsonify(firewall.confirmar_mudanca_interface())

@app.route('/api/firewall/status_mudanca_interface')
@login_required
@tratar_erros
def api_status_mudanca_interface():
    return jsonify(firewall.status_mudanca_interface())

# ══════════════════════════════════════════════════════════
# TOR
# ══════════════════════════════════════════════════════════

@app.route('/tor')
@login_required
def pagina_tor():
    return render_template('tor.html')

@app.route('/api/tor/status')
@login_required
@tratar_erros
def api_tor_status():
    return jsonify({'sucesso': True, 'status': tor.obter_status()})

@app.route('/api/tor/diagnostico')
@login_required
@tratar_erros
def api_tor_diagnostico():
    return jsonify(tor.obter_diagnostico())

@app.route('/api/tor/reparar_firewall', methods=['POST'])
@login_required
@tratar_erros
def api_tor_reparar_fw():
    return jsonify(tor.reparar_firewall())

@app.route('/api/tor/ativar', methods=['POST'])
@login_required
@tratar_erros
def api_tor_ativar():
    return jsonify(tor.ativar())

@app.route('/api/tor/desativar', methods=['POST'])
@login_required
@tratar_erros
def api_tor_desativar():
    return jsonify(tor.desativar())

@app.route('/api/tor/adicionar_servico', methods=['POST'])
@login_required
@tratar_erros
def api_tor_adicionar():
    d = _json()
    return jsonify(tor.adicionar_servico(
        d.get('nome', ''), d.get('porta_virtual', 80),
        d.get('porta_destino', 80), d.get('interface', 'localhost'),
        d.get('ip_destino_custom', '')
    ))

@app.route('/api/tor/editar_servico', methods=['POST'])
@login_required
@tratar_erros
def api_tor_editar():
    d = _json()
    return jsonify(tor.editar_servico(
        d.get('nome_original', ''), d.get('nome_novo', ''),
        d.get('porta_virtual', 80), d.get('porta_destino', 80),
        d.get('interface', 'localhost'),
        d.get('ip_destino_custom', '')
    ))

@app.route('/api/tor/remover_servico', methods=['POST'])
@login_required
@tratar_erros
def api_tor_remover():
    return jsonify(tor.remover_servico(_json().get('nome', '')))

@app.route('/api/tor/pausar_servico', methods=['POST'])
@login_required
@tratar_erros
def api_tor_pausar():
    return jsonify(tor.pausar_servico(_json().get('nome', '')))

@app.route('/api/tor/renovar_onion', methods=['POST'])
@login_required
@tratar_erros
def api_tor_renovar():
    return jsonify(tor.renovar_onion(_json().get('nome', '')))

@app.route('/api/tor/obter_onion', methods=['POST'])
@login_required
@tratar_erros
def api_tor_onion():
    return jsonify(tor.obter_onion(_json().get('nome', '')))

# ══════════════════════════════════════════════════════════
# TOX (acesso remoto)
# ══════════════════════════════════════════════════════════

@app.route('/tox')
@login_required
def pagina_tox():
    return render_template('tox.html')

@app.route('/api/tox/status')
@login_required
@tratar_erros
def api_tox_status():
    return jsonify({'sucesso': True, 'status': tox.obter_status()})

@app.route('/api/tox/diagnostico')
@login_required
@tratar_erros
def api_tox_diagnostico():
    return jsonify(tox.obter_diagnostico())

@app.route('/api/tox/instalar_dependencias', methods=['POST'])
@login_required
@tratar_erros
def api_tox_instalar():
    return jsonify(tox.instalar_dependencias())

@app.route('/api/tox/ativar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_ativar():
    return jsonify(tox.ativar())

@app.route('/api/tox/desativar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_desativar():
    return jsonify(tox.desativar())

@app.route('/api/tox/reparar_firewall', methods=['POST'])
@login_required
@tratar_erros
def api_tox_reparar_fw():
    return jsonify(tox.reparar_firewall())

@app.route('/api/tox/chave/renovar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_renovar():
    return jsonify(tox.renovar_nospam())

@app.route('/api/tox/chave/excluir', methods=['POST'])
@login_required
@tratar_erros
def api_tox_excluir_chave():
    return jsonify(tox.reiniciar_identidade())

@app.route('/api/tox/amigos/adicionar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_amigo_add():
    d = _json()
    return jsonify(tox.adicionar_amigo(d.get('endereco', ''),
                                       d.get('mensagem', 'RRFS')))

@app.route('/api/tox/amigos/remover', methods=['POST'])
@login_required
@tratar_erros
def api_tox_amigo_rem():
    return jsonify(tox.remover_amigo(_json().get('numero')))

@app.route('/api/tox/amigos/aprovar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_amigo_aprovar():
    return jsonify(tox.aprovar_pedido(_json().get('chave', '')))

@app.route('/api/tox/amigos/rejeitar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_amigo_rejeitar():
    return jsonify(tox.rejeitar_pedido(_json().get('chave', '')))

@app.route('/api/tox/aceitar_automatico', methods=['POST'])
@login_required
@tratar_erros
def api_tox_auto():
    return jsonify(
        tox.definir_aceitar_automatico(_json().get('ativo', False))
    )

@app.route('/api/tox/servicos')
@login_required
@tratar_erros
def api_tox_servicos():
    return jsonify(tox.listar_servicos())

@app.route('/api/tox/servicos/testar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_srv_testar():
    return jsonify(tox.testar_servico(_json().get('id', '')))

@app.route('/api/tox/servicos/adicionar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_srv_add():
    d = _json()
    return jsonify(tox.adicionar_servico(
        d.get('nome', ''), d.get('porta', 80),
        d.get('interface', 'localhost'),
        d.get('ip_destino_custom', ''),
        d.get('tipo', 'http'), d.get('esquema', 'http'),
        d.get('comentario', '')
    ))

@app.route('/api/tox/servicos/editar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_srv_edit():
    d = _json()
    return jsonify(tox.editar_servico(
        d.get('id', ''), d.get('nome', ''), d.get('porta', 80),
        d.get('interface', 'localhost'),
        d.get('ip_destino_custom', ''),
        d.get('esquema'), d.get('comentario')
    ))

@app.route('/api/tox/servicos/remover', methods=['POST'])
@login_required
@tratar_erros
def api_tox_srv_rem():
    return jsonify(tox.remover_servico(_json().get('id', '')))

@app.route('/api/tox/servicos/alternar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_srv_alt():
    return jsonify(tox.alternar_servico(_json().get('id', '')))

@app.route('/api/tox/bootstrap')
@login_required
@tratar_erros
def api_tox_nos():
    return jsonify(tox.listar_nos())

@app.route('/api/tox/bootstrap/atualizar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_nos_atualizar():
    return jsonify(tox.atualizar_nos_online())

@app.route('/api/tox/bootstrap/adicionar', methods=['POST'])
@login_required
@tratar_erros
def api_tox_nos_add():
    d = _json()
    return jsonify(tox.adicionar_no(d.get('ip', ''), d.get('porta', 33445),
                                    d.get('chave_publica', '')))

@app.route('/api/tox/bootstrap/remover', methods=['POST'])
@login_required
@tratar_erros
def api_tox_nos_rem():
    return jsonify(tox.remover_no(_json().get('indice')))

# ══════════════════════════════════════════════════════════
# DNS SEGURO
# ══════════════════════════════════════════════════════════

@app.route('/dns')
@login_required
def pagina_dns():
    return render_template('dns.html')

@app.route('/api/dns/status')
@login_required
@tratar_erros
def api_dns_status():
    return jsonify({'sucesso': True, **dns.obter_status()})

@app.route('/api/dns/ativar', methods=['POST'])
@login_required
@tratar_erros
def api_dns_ativar():
    return jsonify(dns.ativar())

@app.route('/api/dns/desativar', methods=['POST'])
@login_required
@tratar_erros
def api_dns_desativar():
    return jsonify(dns.desativar())

@app.route('/api/dns/configurar_porta', methods=['POST'])
@login_required
@tratar_erros
def api_dns_porta():
    d = _json()
    return jsonify(dns.configurar_porta(
        d.get('porta', 53), d.get('tem_filtro_externo', False)
    ))

@app.route('/api/dns/estatisticas')
@login_required
@tratar_erros
def api_dns_estatisticas():
    return jsonify({'sucesso': True, **dns.obter_estatisticas()})

@app.route('/api/dns/cache')
@login_required
@tratar_erros
def api_dns_cache():
    return jsonify({'sucesso': True, 'cache': dns.obter_cache()})

@app.route('/api/dns/limpar_cache', methods=['POST'])
@login_required
@tratar_erros
def api_dns_limpar_cache():
    return jsonify(dns.limpar_cache())

# ══════════════════════════════════════════════════════════
# ANTIVÍRUS
# ══════════════════════════════════════════════════════════

@app.route('/antivirus')
@login_required
def pagina_antivirus():
    return render_template('antivirus.html')

@app.route('/api/antivirus/status')
@login_required
@tratar_erros
def api_av_status():
    return jsonify({'sucesso': True, **antivirus.obter_status()})

@app.route('/api/antivirus/instalar', methods=['POST'])
@login_required
@tratar_erros
def api_av_instalar():
    return jsonify(antivirus.instalar())

@app.route('/api/antivirus/atualizar_db', methods=['POST'])
@login_required
@tratar_erros
def api_av_atualizar():
    return jsonify(antivirus.atualizar_banco())

@app.route('/api/antivirus/escanear', methods=['POST'])
@login_required
@tratar_erros
def api_av_escanear():
    d = _json()
    return jsonify(antivirus.iniciar_scan(
        d.get('caminho', '/'), d.get('tipo', 'completo')
    ))

@app.route('/api/antivirus/scan_status')
@login_required
@tratar_erros
def api_av_scan_status():
    return jsonify({'sucesso': True, **antivirus.status_scan()})

@app.route('/api/antivirus/quarentena')
@login_required
@tratar_erros
def api_av_quarentena():
    return jsonify({'sucesso': True,
                    'quarentena': antivirus.listar_quarentena()})

@app.route('/api/antivirus/restaurar', methods=['POST'])
@login_required
@tratar_erros
def api_av_restaurar():
    return jsonify(antivirus.restaurar_quarentena(_json().get('id', '')))

@app.route('/api/antivirus/remover_quarentena', methods=['POST'])
@login_required
@tratar_erros
def api_av_remover_q():
    return jsonify(antivirus.remover_quarentena(_json().get('id', '')))

@app.route('/api/antivirus/protecao_tempo_real', methods=['POST'])
@login_required
@tratar_erros
def api_av_protecao():
    return jsonify(antivirus.configurar_protecao_tempo_real(
        _json().get('ativo', True)
    ))

@app.route('/api/antivirus/caminhos', methods=['POST'])
@login_required
@tratar_erros
def api_av_caminhos():
    d = _json()
    return jsonify(antivirus.gerenciar_caminho(
        d.get('acao', 'adicionar'), d.get('caminho', '')
    ))

# ══════════════════════════════════════════════════════════
# SELINUX / APPARMOR
# ══════════════════════════════════════════════════════════

@app.route('/selinux')
@login_required
def pagina_selinux():
    return render_template('selinux.html')

@app.route('/api/selinux/status')
@login_required
@tratar_erros
def api_selinux_status():
    return jsonify({'sucesso': True, **selinux.obter_status()})

@app.route('/api/selinux/ativar', methods=['POST'])
@login_required
@tratar_erros
def api_selinux_ativar():
    return jsonify(selinux.ativar())

@app.route('/api/selinux/desativar', methods=['POST'])
@login_required
@tratar_erros
def api_selinux_desativar():
    return jsonify(selinux.desativar())

@app.route('/api/selinux/perfis')
@login_required
@tratar_erros
def api_selinux_perfis():
    return jsonify({'sucesso': True, 'perfis': selinux.listar_perfis()})

@app.route('/api/selinux/gerenciar_perfil', methods=['POST'])
@login_required
@tratar_erros
def api_selinux_perfil():
    d = _json()
    return jsonify(selinux.gerenciar_perfil(
        d.get('perfil', ''), d.get('acao', 'enforce')
    ))

# ══════════════════════════════════════════════════════════
# IMPORTAR / EXPORTAR
# ══════════════════════════════════════════════════════════

@app.route('/api/config/exportar', methods=['POST'])
@login_required
@tratar_erros
def api_exportar():
    from modulos.config_io import exportar_configuracoes
    resultado = exportar_configuracoes(
        BASE_DIR, _json().get('categorias', [])
    )
    if not resultado['sucesso']:
        return jsonify(resultado)

    arquivo = resultado['arquivo']

    @after_this_request
    def _apagar(resp):
        try:
            os.remove(arquivo)
        except OSError:
            pass
        return resp

    return send_file(arquivo, as_attachment=True,
                     download_name='rrfs_config_export.json',
                     mimetype='application/json')

@app.route('/api/config/importar', methods=['POST'])
@login_required
@tratar_erros
def api_importar():
    from modulos.config_io import importar_configuracoes
    if 'arquivo' not in request.files:
        return jsonify({'sucesso': False, 'erro': 'Arquivo não enviado'})
    conteudo = request.files['arquivo'].read().decode('utf-8')
    return jsonify(importar_configuracoes(
        BASE_DIR, conteudo, request.form.getlist('categorias'),
        firewall, tor, tox
    ))

@app.route('/api/config/preview_importar', methods=['POST'])
@login_required
@tratar_erros
def api_preview_importar():
    from modulos.config_io import preview_importacao
    if 'arquivo' not in request.files:
        return jsonify({'sucesso': False, 'erro': 'Arquivo não enviado'})
    return jsonify(preview_importacao(
        request.files['arquivo'].read().decode('utf-8')
    ))

# ══════════════════════════════════════════════════════════
# MANUTENÇÃO AUTOMÁTICA
# ══════════════════════════════════════════════════════════

def _configurar_atualizacao_automatica():
    """Atualização automática diária do sistema"""
    try:
        cron = (
            '# RRFS - Atualização automática do sistema\n'
            '0 2 * * * root apt-get update -qq '
            '>> /var/log/rrfs-update.log 2>&1\n'
            '0 3 * * * root DEBIAN_FRONTEND=noninteractive '
            'apt-get upgrade -y -qq '
            '>> /var/log/rrfs-update.log 2>&1\n'
            '0 4 * * 0 root apt-get autoremove -y -qq '
            '>> /var/log/rrfs-update.log 2>&1\n'
        )
        with open('/etc/cron.d/rrfs-updates', 'w') as f:
            f.write(cron)
        os.chmod('/etc/cron.d/rrfs-updates', 0o644)
    except Exception as e:
        logger.error(f"_configurar_atualizacao: {e}")


def _limpar_legado_conexao():
    """Remove restos do antigo conexao.py (VPN de acesso/saída)."""
    try:
        for svc in ('rrfs-vpn-acesso', 'rrfs-vpn'):
            executar_comando(
                f'systemctl disable --now {svc} 2>/dev/null', timeout=15
            )
        executar_comando(
            'pkill -f openvpn-rrfs 2>/dev/null', timeout=5
        )
    except Exception as e:
        logger.error(f"_limpar_legado_conexao: {e}")

# ══════════════════════════════════════════════════════════
# INICIALIZAÇÃO
# ══════════════════════════════════════════════════════════

def inicializar_sistema():
    cert, key = garantir_ssl()
    firewall.inicializar()
    firewall.garantir_regra_sistema()
    _configurar_atualizacao_automatica()
    _limpar_legado_conexao()
    tox.restaurar()          # religa o Tox se estava ativo
    return cert, key


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("❌ Execute como root: sudo python3 app.py")
        sys.exit(1)

    print("""
╔══════════════════════════════════════════════════════════╗
║          RRFS Servidores v2.5                           ║
║          Sistema de Segurança de Rede                   ║
╚══════════════════════════════════════════════════════════╝
    """)

    cert, key = inicializar_sistema()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)

    print("🔒 HTTPS → https://0.0.0.0:2000")
    print(f"📋 Logs  → {LOG_FILE}")

    app.run(host='0.0.0.0', port=2000, ssl_context=ctx,
            debug=False, threaded=True)
