#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RRFS Servidores v2.0
"""

import os
import sys
import ssl
import logging
import subprocess
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file
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

# handler de arquivo - apenas ERROR e acima
_file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
_file_handler.setLevel(logging.ERROR)
_file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    datefmt='%d/%m/%Y %H:%M:%S'
))

# ── silenciar loggers do Flask/Werkzeug completamente ──
for _nome in [
    'werkzeug',
    'werkzeug.serving',
    'werkzeug.routing',
    'flask',
    'flask.app',
    'urllib3',
    'urllib3.connectionpool',
    'requests',
    'charset_normalizer',
]:
    _lg = logging.getLogger(_nome)
    _lg.setLevel(logging.CRITICAL + 1)
    _lg.propagate = False
    _lg.handlers  = []

# ── logger raiz: só erros, só no arquivo ──
_root = logging.getLogger()
_root.setLevel(logging.ERROR)
_root.handlers = []
_root.addHandler(_file_handler)

# ── logger da aplicação ──
logger = logging.getLogger('RRFS')
logger.setLevel(logging.ERROR)
logger.propagate = True

# ── módulos ────────────────────────────────────────────────
sys.path.insert(0, BASE_DIR)
from modulos.utils        import executar_comando, gerar_ssl
from modulos.firewall_ufw import FirewallUFW
from modulos.tor_manager  import TorManager
from modulos.conexao      import ConexaoManager
from modulos.dns_seguro   import DNSSeguro
from modulos.antivirus    import AntivirusManager
from modulos.selinux      import SELinuxManager

# ── Flask ──────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32)
app.permanent_session_lifetime = timedelta(hours=8)

# desativar log do Flask completamente
app.logger.handlers  = []
app.logger.propagate = False
app.logger.setLevel(logging.CRITICAL + 1)

import logging as _logging
_logging.getLogger('werkzeug').disabled = True

# ── instâncias ─────────────────────────────────────────────
firewall  = FirewallUFW(BASE_DIR)
tor       = TorManager(BASE_DIR)
conexao   = ConexaoManager(BASE_DIR)
dns       = DNSSeguro(BASE_DIR)
antivirus = AntivirusManager(BASE_DIR)
selinux   = SELinuxManager(BASE_DIR)

tor.set_firewall_ufw(firewall)
conexao.set_firewall(firewall)
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

def verificar_senha_root(senha):
    try:
        # método via PAM/su
        proc = subprocess.run(
            ['su', '-c', 'true', 'root'],
            input=senha + '\n',
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            return True
        # método alternativo via python-pam
        proc2 = subprocess.run(
            ['python3', '-c',
             f"import pam; p=pam.pam(); "
             f"exit(0 if p.authenticate('root','{senha}') else 1)"],
            capture_output=True, text=True, timeout=10
        )
        return proc2.returncode == 0
    except Exception as e:
        logger.error(f"verificar_senha_root: {e}")
    return False


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logado'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════
# ROTAS - LOGIN
# ══════════════════════════════════════════════════════════

@app.route('/', methods=['GET', 'POST'])
def login():
    erro = None
    if request.method == 'POST':
        senha = request.form.get('senha', '')
        if verificar_senha_root(senha):
            session.permanent = True
            session['logado'] = True
            session['login_em'] = datetime.now().isoformat()
            return redirect(url_for('dashboard'))
        else:
            erro = 'Senha incorreta'
            logger.error(
                f"Login falhou - IP: {request.remote_addr}"
            )
    return render_template('login.html', erro=erro)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ══════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/status_geral')
@login_required
def api_status_geral():
    try:
        return jsonify({
            'sucesso':    True,
            'ufw':        firewall.obter_status(),
            'tor':        tor.obter_status(),
            'conexao':    conexao.obter_status(),
            'dns':        dns.obter_status_resumido(),
            'antivirus':  antivirus.obter_status_resumido(),
            'selinux':    selinux.obter_status(),
            'regras_count': len(firewall.listar_regras_salvas()),
            'ip_publico': _obter_ip_publico(),
            'sistema':    _info_sistema(),
            'timestamp':  datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        })
    except Exception as e:
        logger.error(f"api_status_geral: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/tor/diagnostico')
@login_required
def api_tor_diagnostico():
    try:
        return jsonify(tor.obter_diagnostico())
    except Exception as e:
        logger.error(f"api_tor_diagnostico: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/tor/reparar_firewall', methods=['POST'])
@login_required
def api_tor_reparar_fw():
    try:
        return jsonify(tor.reparar_firewall())
    except Exception as e:
        logger.error(f"api_tor_reparar_fw: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


def _obter_ip_publico():
    try:
        r = executar_comando(
            'curl -s --max-time 5 https://api.ipify.org'
        )
        if r['sucesso'] and r['saida']:
            return r['saida'].strip()
    except Exception as e:
        logger.error(f"_obter_ip_publico: {e}")
    return 'N/A'


def _info_sistema():
    try:
        uptime = executar_comando('uptime -p')
        mem    = executar_comando(
            "free -h | grep Mem | awk '{print $3\"/\"$2}'"
        )
        cpu    = executar_comando(
            "top -bn1 | grep 'Cpu' | awk '{print $2}'"
        )
        disk   = executar_comando(
            "df -h / | tail -1 | awk '{print $3\"/\"$2}'"
        )
        return {
            'uptime':  uptime.get('saida', 'N/A'),
            'memoria': mem.get('saida', 'N/A'),
            'cpu':     cpu.get('saida', 'N/A') + '%',
            'disco':   disk.get('saida', 'N/A'),
        }
    except Exception as e:
        logger.error(f"_info_sistema: {e}")
        return {}

# ══════════════════════════════════════════════════════════
# FIREWALL
# ══════════════════════════════════════════════════════════

@app.route('/firewall')
@login_required
def pagina_firewall():
    return render_template('firewall.html')

@app.route('/api/firewall/status')
@login_required
def api_firewall_status():
    try:
        return jsonify({
            'sucesso':    True,
            'status':     firewall.obter_status(),
            'regras':     firewall.listar_regras_salvas(),
            'interfaces': conexao.listar_interfaces()
        })
    except Exception as e:
        logger.error(f"api_firewall_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/adicionar', methods=['POST'])
@login_required
def api_firewall_adicionar():
    try:
        return jsonify(firewall.adicionar_regra(request.get_json()))
    except Exception as e:
        logger.error(f"api_firewall_adicionar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/remover', methods=['POST'])
@login_required
def api_firewall_remover():
    try:
        d = request.get_json()
        return jsonify(firewall.remover_regra(d.get('indice')))
    except Exception as e:
        logger.error(f"api_firewall_remover: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/pausar', methods=['POST'])
@login_required
def api_firewall_pausar():
    try:
        d = request.get_json()
        return jsonify(firewall.pausar_regra(d.get('indice')))
    except Exception as e:
        logger.error(f"api_firewall_pausar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/reativar', methods=['POST'])
@login_required
def api_firewall_reativar():
    try:
        d = request.get_json()
        return jsonify(firewall.reativar_regra(d.get('indice')))
    except Exception as e:
        logger.error(f"api_firewall_reativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/editar', methods=['POST'])
@login_required
def api_firewall_editar():
    try:
        return jsonify(firewall.editar_regra(request.get_json()))
    except Exception as e:
        logger.error(f"api_firewall_editar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/config_interface', methods=['POST'])
@login_required
def api_config_interface():
    try:
        d = request.get_json()
        return jsonify(
            firewall.iniciar_mudanca_interface(d.get('interface',''))
        )
    except Exception as e:
        logger.error(f"api_config_interface: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/confirmar_interface', methods=['POST'])
@login_required
def api_confirmar_interface():
    try:
        return jsonify(firewall.confirmar_mudanca_interface())
    except Exception as e:
        logger.error(f"api_confirmar_interface: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/firewall/status_mudanca_interface')
@login_required
def api_status_mudanca_interface():
    try:
        return jsonify(firewall.status_mudanca_interface())
    except Exception as e:
        logger.error(f"api_status_mudanca_interface: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# TOR
# ══════════════════════════════════════════════════════════

@app.route('/tor')
@login_required
def pagina_tor():
    return render_template('tor.html')

@app.route('/api/tor/status')
@login_required
def api_tor_status():
    try:
        return jsonify({'sucesso': True, 'status': tor.obter_status()})
    except Exception as e:
        logger.error(f"api_tor_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/ativar', methods=['POST'])
@login_required
def api_tor_ativar():
    try:
        return jsonify(tor.ativar())
    except Exception as e:
        logger.error(f"api_tor_ativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/desativar', methods=['POST'])
@login_required
def api_tor_desativar():
    try:
        return jsonify(tor.desativar())
    except Exception as e:
        logger.error(f"api_tor_desativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/adicionar_servico', methods=['POST'])
@login_required
def api_tor_adicionar():
    try:
        d = request.get_json()
        return jsonify(tor.adicionar_servico(
            d.get('nome',''), d.get('porta_virtual',80),
            d.get('porta_destino',80), d.get('interface','localhost')
        ))
    except Exception as e:
        logger.error(f"api_tor_adicionar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/editar_servico', methods=['POST'])
@login_required
def api_tor_editar():
    try:
        d = request.get_json()
        return jsonify(tor.editar_servico(
            d.get('nome_original',''), d.get('nome_novo',''),
            d.get('porta_virtual',80), d.get('porta_destino',80),
            d.get('interface','localhost')
        ))
    except Exception as e:
        logger.error(f"api_tor_editar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/remover_servico', methods=['POST'])
@login_required
def api_tor_remover():
    try:
        d = request.get_json()
        return jsonify(tor.remover_servico(d.get('nome','')))
    except Exception as e:
        logger.error(f"api_tor_remover: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/pausar_servico', methods=['POST'])
@login_required
def api_tor_pausar():
    try:
        d = request.get_json()
        return jsonify(tor.pausar_servico(d.get('nome','')))
    except Exception as e:
        logger.error(f"api_tor_pausar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/renovar_onion', methods=['POST'])
@login_required
def api_tor_renovar():
    try:
        d = request.get_json()
        return jsonify(tor.renovar_onion(d.get('nome','')))
    except Exception as e:
        logger.error(f"api_tor_renovar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/tor/obter_onion', methods=['POST'])
@login_required
def api_tor_onion():
    try:
        d = request.get_json()
        return jsonify(tor.obter_onion(d.get('nome','')))
    except Exception as e:
        logger.error(f"api_tor_onion: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# CONEXÃO
# ══════════════════════════════════════════════════════════

@app.route('/conexao')
@login_required
def pagina_conexao():
    return render_template('conexao.html')

@app.route('/api/conexao/status')
@login_required
def api_conexao_status():
    try:
        return jsonify({'sucesso': True, **conexao.obter_status()})
    except Exception as e:
        logger.error(f"api_conexao_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/interfaces')
@login_required
def api_interfaces():
    try:
        return jsonify({
            'sucesso': True,
            'interfaces': conexao.listar_interfaces()
        })
    except Exception as e:
        logger.error(f"api_interfaces: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/redes_wifi', methods=['POST'])
@login_required
def api_redes_wifi():
    try:
        d = request.get_json()
        return jsonify({
            'sucesso': True,
            'redes': conexao.escanear_wifi(d.get('interface',''))
        })
    except Exception as e:
        logger.error(f"api_redes_wifi: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/configurar_wan', methods=['POST'])
@login_required
def api_configurar_wan():
    try:
        return jsonify(conexao.configurar_wan(request.get_json()))
    except Exception as e:
        logger.error(f"api_configurar_wan: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/conectar_wifi', methods=['POST'])
@login_required
def api_conectar_wifi():
    try:
        return jsonify(conexao.conectar_wifi(request.get_json()))
    except Exception as e:
        logger.error(f"api_conectar_wifi: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn/importar', methods=['POST'])
@login_required
def api_vpn_importar():
    try:
        if 'arquivo' not in request.files:
            return jsonify({'sucesso': False, 'erro': 'Arquivo não enviado'})
        f        = request.files['arquivo']
        conteudo = f.read().decode('utf-8', errors='replace')
        return jsonify(conexao.importar_vpn_saida(
            request.form.get('nome', f.filename),
            conteudo,
            request.form.get('usuario', ''),
            request.form.get('senha', '')
        ))
    except Exception as e:
        logger.error(f"api_vpn_importar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn/listar')
@login_required
def api_vpn_listar():
    try:
        return jsonify({'sucesso': True, 'vpns': conexao.listar_vpns_saida()})
    except Exception as e:
        logger.error(f"api_vpn_listar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn/remover', methods=['POST'])
@login_required
def api_vpn_remover():
    try:
        d = request.get_json()
        return jsonify(conexao.remover_vpn_saida(d.get('id','')))
    except Exception as e:
        logger.error(f"api_vpn_remover: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn/conectar', methods=['POST'])
@login_required
def api_vpn_conectar():
    try:
        d = request.get_json()
        return jsonify(conexao.conectar_vpn(d.get('id','')))
    except Exception as e:
        logger.error(f"api_vpn_conectar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn/desconectar', methods=['POST'])
@login_required
def api_vpn_desconectar():
    try:
        return jsonify(conexao.desconectar_vpn())
    except Exception as e:
        logger.error(f"api_vpn_desconectar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn/portas_saida', methods=['POST'])
@login_required
def api_vpn_portas_saida():
    try:
        d = request.get_json()
        return jsonify(conexao.configurar_portas_saida_vpn(
            d.get('id',''), d.get('portas',[])
        ))
    except Exception as e:
        logger.error(f"api_vpn_portas_saida: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn_acesso/configurar', methods=['POST'])
@login_required
def api_vpn_acesso_configurar():
    try:
        return jsonify(conexao.configurar_vpn_acesso(request.get_json()))
    except Exception as e:
        logger.error(f"api_vpn_acesso_configurar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn_acesso/status')
@login_required
def api_vpn_acesso_status():
    try:
        return jsonify(conexao.status_vpn_acesso())
    except Exception as e:
        logger.error(f"api_vpn_acesso_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn_acesso/baixar_ovpn')
@login_required
def api_vpn_acesso_baixar():
    try:
        r = conexao.gerar_ovpn_acesso()
        if not r['sucesso']:
            return jsonify(r)
        return send_file(
            r['arquivo'], as_attachment=True,
            download_name='rrfs_acesso.ovpn',
            mimetype='application/x-openvpn-profile'
        )
    except Exception as e:
        logger.error(f"api_vpn_acesso_baixar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn_acesso/ativar', methods=['POST'])
@login_required
def api_vpn_acesso_ativar():
    try:
        return jsonify(conexao.ativar_vpn_acesso())
    except Exception as e:
        logger.error(f"api_vpn_acesso_ativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/vpn_acesso/desativar', methods=['POST'])
@login_required
def api_vpn_acesso_desativar():
    try:
        return jsonify(conexao.desativar_vpn_acesso())
    except Exception as e:
        logger.error(f"api_vpn_acesso_desativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/modo', methods=['POST'])
@login_required
def api_modo_conexao():
    try:
        d = request.get_json()
        return jsonify(conexao.aplicar_modo(
            d.get('modo','direto'), d.get('vpn_id', None)
        ))
    except Exception as e:
        logger.error(f"api_modo_conexao: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/redes_salvas')
@login_required
def api_redes_salvas():
    try:
        return jsonify({
            'sucesso': True,
            'redes':   conexao.listar_redes_salvas()
        })
    except Exception as e:
        logger.error(f"api_redes_salvas: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/remover_rede', methods=['POST'])
@login_required
def api_remover_rede():
    try:
        d = request.get_json()
        return jsonify(
            conexao.remover_rede_salva(d.get('id', ''))
        )
    except Exception as e:
        logger.error(f"api_remover_rede: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/reconectar_rede', methods=['POST'])
@login_required
def api_reconectar_rede():
    try:
        d = request.get_json()
        return jsonify(
            conexao.reconectar_rede(d.get('id', ''))
        )
    except Exception as e:
        logger.error(f"api_reconectar_rede: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/conexao/gerar_mac')
@login_required
def api_gerar_mac():
    """Gera MAC aleatório válido"""
    from modulos.conexao import _gerar_mac_aleatorio
    return jsonify({
        'sucesso': True,
        'mac':     _gerar_mac_aleatorio()
    })

# ══════════════════════════════════════════════════════════
# DNS SEGURO
# ══════════════════════════════════════════════════════════

@app.route('/dns')
@login_required
def pagina_dns():
    return render_template('dns.html')

@app.route('/api/dns/status')
@login_required
def api_dns_status():
    try:
        return jsonify({'sucesso': True, **dns.obter_status()})
    except Exception as e:
        logger.error(f"api_dns_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/dns/ativar', methods=['POST'])
@login_required
def api_dns_ativar():
    try:
        return jsonify(dns.ativar())
    except Exception as e:
        logger.error(f"api_dns_ativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/dns/desativar', methods=['POST'])
@login_required
def api_dns_desativar():
    try:
        return jsonify(dns.desativar())
    except Exception as e:
        logger.error(f"api_dns_desativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/dns/configurar_porta', methods=['POST'])
@login_required
def api_dns_porta():
    try:
        d = request.get_json()
        return jsonify(dns.configurar_porta(
            d.get('porta', 53),
            d.get('tem_filtro_externo', False)
        ))
    except Exception as e:
        logger.error(f"api_dns_porta: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/dns/estatisticas')
@login_required
def api_dns_estatisticas():
    try:
        return jsonify({'sucesso': True, **dns.obter_estatisticas()})
    except Exception as e:
        logger.error(f"api_dns_estatisticas: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/dns/cache')
@login_required
def api_dns_cache():
    try:
        return jsonify({'sucesso': True, 'cache': dns.obter_cache()})
    except Exception as e:
        logger.error(f"api_dns_cache: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/dns/limpar_cache', methods=['POST'])
@login_required
def api_dns_limpar_cache():
    try:
        return jsonify(dns.limpar_cache())
    except Exception as e:
        logger.error(f"api_dns_limpar_cache: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# ANTIVÍRUS
# ══════════════════════════════════════════════════════════

@app.route('/antivirus')
@login_required
def pagina_antivirus():
    return render_template('antivirus.html')

@app.route('/api/antivirus/status')
@login_required
def api_av_status():
    try:
        return jsonify({'sucesso': True, **antivirus.obter_status()})
    except Exception as e:
        logger.error(f"api_av_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/instalar', methods=['POST'])
@login_required
def api_av_instalar():
    try:
        return jsonify(antivirus.instalar())
    except Exception as e:
        logger.error(f"api_av_instalar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/atualizar_db', methods=['POST'])
@login_required
def api_av_atualizar():
    try:
        return jsonify(antivirus.atualizar_banco())
    except Exception as e:
        logger.error(f"api_av_atualizar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/escanear', methods=['POST'])
@login_required
def api_av_escanear():
    try:
        d = request.get_json()
        return jsonify(antivirus.iniciar_scan(
            d.get('caminho', '/'),
            d.get('tipo', 'completo')
        ))
    except Exception as e:
        logger.error(f"api_av_escanear: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/scan_status')
@login_required
def api_av_scan_status():
    try:
        return jsonify({'sucesso': True, **antivirus.status_scan()})
    except Exception as e:
        logger.error(f"api_av_scan_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/quarentena')
@login_required
def api_av_quarentena():
    try:
        return jsonify({
            'sucesso': True,
            'quarentena': antivirus.listar_quarentena()
        })
    except Exception as e:
        logger.error(f"api_av_quarentena: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/restaurar', methods=['POST'])
@login_required
def api_av_restaurar():
    try:
        d = request.get_json()
        return jsonify(antivirus.restaurar_quarentena(d.get('id','')))
    except Exception as e:
        logger.error(f"api_av_restaurar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/remover_quarentena', methods=['POST'])
@login_required
def api_av_remover_q():
    try:
        d = request.get_json()
        return jsonify(
            antivirus.remover_quarentena(d.get('id',''))
        )
    except Exception as e:
        logger.error(f"api_av_remover_q: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/protecao_tempo_real', methods=['POST'])
@login_required
def api_av_protecao():
    try:
        d = request.get_json()
        return jsonify(
            antivirus.configurar_protecao_tempo_real(
                d.get('ativo', True)
            )
        )
    except Exception as e:
        logger.error(f"api_av_protecao: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/antivirus/caminhos', methods=['POST'])
@login_required
def api_av_caminhos():
    try:
        d = request.get_json()
        acao    = d.get('acao', 'adicionar')
        caminho = d.get('caminho', '')
        return jsonify(
            antivirus.gerenciar_caminho(acao, caminho)
        )
    except Exception as e:
        logger.error(f"api_av_caminhos: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# SELINUX / APPARMOR
# ══════════════════════════════════════════════════════════

@app.route('/selinux')
@login_required
def pagina_selinux():
    return render_template('selinux.html')

@app.route('/api/selinux/status')
@login_required
def api_selinux_status():
    try:
        return jsonify({'sucesso': True, **selinux.obter_status()})
    except Exception as e:
        logger.error(f"api_selinux_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/selinux/ativar', methods=['POST'])
@login_required
def api_selinux_ativar():
    try:
        return jsonify(selinux.ativar())
    except Exception as e:
        logger.error(f"api_selinux_ativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/selinux/desativar', methods=['POST'])
@login_required
def api_selinux_desativar():
    try:
        return jsonify(selinux.desativar())
    except Exception as e:
        logger.error(f"api_selinux_desativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/selinux/perfis')
@login_required
def api_selinux_perfis():
    try:
        return jsonify({
            'sucesso': True,
            'perfis': selinux.listar_perfis()
        })
    except Exception as e:
        logger.error(f"api_selinux_perfis: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/selinux/gerenciar_perfil', methods=['POST'])
@login_required
def api_selinux_perfil():
    try:
        d = request.get_json()
        return jsonify(selinux.gerenciar_perfil(
            d.get('perfil',''), d.get('acao','enforce')
        ))
    except Exception as e:
        logger.error(f"api_selinux_perfil: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# IMPORTAR / EXPORTAR
# ══════════════════════════════════════════════════════════

@app.route('/api/config/exportar', methods=['POST'])
@login_required
def api_exportar():
    try:
        from modulos.config_io import exportar_configuracoes
        d         = request.get_json()
        categorias = d.get('categorias', [])
        resultado  = exportar_configuracoes(
            BASE_DIR, categorias
        )
        if not resultado['sucesso']:
            return jsonify(resultado)
        return send_file(
            resultado['arquivo'],
            as_attachment=True,
            download_name='rrfs_config_export.json',
            mimetype='application/json'
        )
    except Exception as e:
        logger.error(f"api_exportar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/config/importar', methods=['POST'])
@login_required
def api_importar():
    try:
        from modulos.config_io import importar_configuracoes
        if 'arquivo' not in request.files:
            return jsonify({'sucesso': False, 'erro': 'Arquivo não enviado'})
        f          = request.files['arquivo']
        categorias = request.form.getlist('categorias')
        conteudo   = f.read().decode('utf-8')
        resultado  = importar_configuracoes(
            BASE_DIR, conteudo, categorias,
            firewall, tor, conexao
        )
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_importar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

@app.route('/api/config/preview_importar', methods=['POST'])
@login_required
def api_preview_importar():
    try:
        from modulos.config_io import preview_importacao
        if 'arquivo' not in request.files:
            return jsonify({'sucesso': False, 'erro': 'Arquivo não enviado'})
        f        = request.files['arquivo']
        conteudo = f.read().decode('utf-8')
        return jsonify(preview_importacao(conteudo))
    except Exception as e:
        logger.error(f"api_preview_importar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# MANUTENÇÃO AUTOMÁTICA
# ══════════════════════════════════════════════════════════

def _configurar_atualizacao_automatica():
    """Atualização automática diária do sistema"""
    try:
        cron = (
            '# RRFS - Atualização automática do sistema\n'
            '# apt update diário às 02:00\n'
            '0 2 * * * root apt-get update -qq '
            '>> /var/log/rrfs-update.log 2>&1\n'
            '# apt upgrade diário às 03:00\n'
            '0 3 * * * root DEBIAN_FRONTEND=noninteractive '
            'apt-get upgrade -y -qq '
            '>> /var/log/rrfs-update.log 2>&1\n'
            '# autoremove semanal (dom 04:00)\n'
            '0 4 * * 0 root apt-get autoremove -y -qq '
            '>> /var/log/rrfs-update.log 2>&1\n'
        )
        with open('/etc/cron.d/rrfs-updates', 'w') as f:
            f.write(cron)
        os.chmod('/etc/cron.d/rrfs-updates', 0o644)
    except Exception as e:
        logger.error(f"_configurar_atualizacao: {e}")

# ══════════════════════════════════════════════════════════
# INICIALIZAÇÃO
# ══════════════════════════════════════════════════════════

def inicializar_sistema():
    cert, key = garantir_ssl()
    firewall.inicializar()
    firewall.garantir_regra_sistema()
    _configurar_atualizacao_automatica()
    return cert, key


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("❌ Execute como root: sudo python3 app.py")
        sys.exit(1)

    print("""
╔══════════════════════════════════════════════════════════╗
║          RRFS Servidores v2.0                           ║
║          Sistema de Segurança de Rede                   ║
╚══════════════════════════════════════════════════════════╝
    """)

    cert, key = inicializar_sistema()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    print(f"🔒 HTTPS → https://0.0.0.0:2000")
    print(f"📋 Logs  → {LOG_FILE}")

    # suprimir output do werkzeug no terminal também
    import logging as _log
    _log.getLogger('werkzeug').setLevel(_log.CRITICAL + 1)

    app.run(
        host='0.0.0.0',
        port=2000,
        ssl_context=ctx,
        debug=False,
        threaded=True
    )
