#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║              RRFS Servidores                             ║
║         Sistema de Segurança de Rede                     ║
║         Versão 1.0                                       ║
╚══════════════════════════════════════════════════════════╝
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

# ── logging: APENAS ERROS ──────────────────────────────────
LOG_FILE = os.path.join(LOGS_DIR, 'erros.log')

file_handler = logging.FileHandler(LOG_FILE, encoding='utf-8')
file_handler.setLevel(logging.ERROR)
file_handler.setFormatter(logging.Formatter(
    '[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    datefmt='%d/%m/%Y %H:%M:%S'
))

# Logger raiz captura tudo acima de ERROR
root_logger = logging.getLogger()
root_logger.setLevel(logging.ERROR)
root_logger.addHandler(file_handler)

logger = logging.getLogger('RRFS')

# ── módulos ────────────────────────────────────────────────
sys.path.insert(0, BASE_DIR)
from modulos.utils        import executar_comando, gerar_ssl
from modulos.firewall_ufw import FirewallUFW
from modulos.tor_manager  import TorManager
from modulos.conexao      import ConexaoManager

# ── Flask ──────────────────────────────────────────────────
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32)
app.permanent_session_lifetime = timedelta(hours=8)

# ── instâncias ─────────────────────────────────────────────
firewall = FirewallUFW(BASE_DIR)
tor      = TorManager(BASE_DIR)
conexao  = ConexaoManager(BASE_DIR)

tor.set_firewall_ufw(firewall)

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
    """Verifica senha do root usando PAM via su"""
    try:
        proc = subprocess.run(
            ['su', '-c', 'true', 'root'],
            input=senha + '\n',
            capture_output=True,
            text=True,
            timeout=10
        )
        if proc.returncode == 0:
            return True
        # Método alternativo: login
        proc2 = subprocess.run(
            ['python3', '-c',
             f"import pam; p=pam.pam(); "
             f"print(p.authenticate('root','{senha}'))"],
            capture_output=True, text=True, timeout=10
        )
        if 'True' in proc2.stdout:
            return True
    except Exception as e:
        logger.error(f"Erro verificar senha root: {e}")
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
            logger.error(f"Tentativa de login falhou - IP: {request.remote_addr}")
    return render_template('login.html', erro=erro)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ══════════════════════════════════════════════════════════
# ROTAS - DASHBOARD
# ══════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/api/status_geral')
@login_required
def api_status_geral():
    try:
        status_ufw = firewall.obter_status()
        status_tor = tor.obter_status()
        status_con = conexao.obter_status()
        regras     = firewall.listar_regras_salvas()
        ip_publico = _obter_ip_publico()
        info_sys   = _info_sistema()

        return jsonify({
            'sucesso': True,
            'ufw': status_ufw,
            'tor': status_tor,
            'conexao': status_con,
            'regras_count': len(regras),
            'ip_publico': ip_publico,
            'sistema': info_sys,
            'timestamp': datetime.now().strftime('%d/%m/%Y %H:%M:%S')
        })
    except Exception as e:
        logger.error(f"api_status_geral: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


def _obter_ip_publico():
    try:
        r = executar_comando(
            'curl -s --max-time 5 https://api.ipify.org'
        )
        if r['sucesso'] and r['saida']:
            return r['saida'].strip()
    except Exception as e:
        logger.error(f"obter_ip_publico: {e}")
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
            'uptime': uptime.get('saida', 'N/A'),
            'memoria': mem.get('saida', 'N/A'),
            'cpu': cpu.get('saida', 'N/A') + '%',
            'disco': disk.get('saida', 'N/A'),
        }
    except Exception as e:
        logger.error(f"_info_sistema: {e}")
        return {}

# ══════════════════════════════════════════════════════════
# ROTAS - FIREWALL
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
            'sucesso': True,
            'status': firewall.obter_status(),
            'regras': firewall.listar_regras_salvas(),
            'interfaces': _listar_interfaces()
        })
    except Exception as e:
        logger.error(f"api_firewall_status: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/firewall/adicionar', methods=['POST'])
@login_required
def api_firewall_adicionar():
    try:
        dados = request.get_json()
        resultado = firewall.adicionar_regra(dados)
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_firewall_adicionar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/firewall/remover', methods=['POST'])
@login_required
def api_firewall_remover():
    try:
        dados = request.get_json()
        idx   = dados.get('indice')
        resultado = firewall.remover_regra(idx)
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_firewall_remover: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/firewall/pausar', methods=['POST'])
@login_required
def api_firewall_pausar():
    try:
        dados = request.get_json()
        idx   = dados.get('indice')
        resultado = firewall.pausar_regra(idx)
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_firewall_pausar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/firewall/reativar', methods=['POST'])
@login_required
def api_firewall_reativar():
    try:
        dados = request.get_json()
        idx   = dados.get('indice')
        resultado = firewall.reativar_regra(idx)
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_firewall_reativar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/firewall/editar', methods=['POST'])
@login_required
def api_firewall_editar():
    try:
        dados = request.get_json()
        resultado = firewall.editar_regra(dados)
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_firewall_editar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


# ── Configuração de interface do sistema ──────────────────

@app.route('/api/firewall/config_interface', methods=['POST'])
@login_required
def api_config_interface():
    try:
        dados     = request.get_json()
        interface = dados.get('interface', '')
        resultado = firewall.iniciar_mudanca_interface(interface)
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_config_interface: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/firewall/confirmar_interface', methods=['POST'])
@login_required
def api_confirmar_interface():
    try:
        resultado = firewall.confirmar_mudanca_interface()
        return jsonify(resultado)
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
# ROTAS - TOR
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
            d.get('nome', ''),
            d.get('porta_virtual', 80),
            d.get('porta_destino', 80),
            d.get('interface', 'localhost')
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
            d.get('nome_original', ''),
            d.get('nome_novo', ''),
            d.get('porta_virtual', 80),
            d.get('porta_destino', 80),
            d.get('interface', 'localhost')
        ))
    except Exception as e:
        logger.error(f"api_tor_editar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/tor/remover_servico', methods=['POST'])
@login_required
def api_tor_remover():
    try:
        d = request.get_json()
        return jsonify(tor.remover_servico(d.get('nome', '')))
    except Exception as e:
        logger.error(f"api_tor_remover: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/tor/pausar_servico', methods=['POST'])
@login_required
def api_tor_pausar():
    try:
        d = request.get_json()
        return jsonify(tor.pausar_servico(d.get('nome', '')))
    except Exception as e:
        logger.error(f"api_tor_pausar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/tor/renovar_onion', methods=['POST'])
@login_required
def api_tor_renovar():
    try:
        d = request.get_json()
        return jsonify(tor.renovar_onion(d.get('nome', '')))
    except Exception as e:
        logger.error(f"api_tor_renovar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/tor/obter_onion', methods=['POST'])
@login_required
def api_tor_onion():
    try:
        d = request.get_json()
        return jsonify(tor.obter_onion(d.get('nome', '')))
    except Exception as e:
        logger.error(f"api_tor_onion: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})

# ══════════════════════════════════════════════════════════
# ROTAS - CONEXÃO
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
        d   = request.get_json()
        ifc = d.get('interface', '')
        return jsonify({
            'sucesso': True,
            'redes': conexao.escanear_wifi(ifc)
        })
    except Exception as e:
        logger.error(f"api_redes_wifi: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/conexao/configurar_wan', methods=['POST'])
@login_required
def api_configurar_wan():
    try:
        d = request.get_json()
        return jsonify(conexao.configurar_wan(d))
    except Exception as e:
        logger.error(f"api_configurar_wan: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/conexao/conectar_wifi', methods=['POST'])
@login_required
def api_conectar_wifi():
    try:
        d = request.get_json()
        return jsonify(conexao.conectar_wifi(d))
    except Exception as e:
        logger.error(f"api_conectar_wifi: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


# ── VPNs de saída ─────────────────────────────────────────

@app.route('/api/conexao/vpn/importar', methods=['POST'])
@login_required
def api_vpn_importar():
    try:
        if 'arquivo' not in request.files:
            return jsonify({'sucesso': False, 'erro': 'Arquivo não enviado'})
        f       = request.files['arquivo']
        nome    = request.form.get('nome', f.filename)
        usuario = request.form.get('usuario', '')
        senha   = request.form.get('senha', '')
        conteudo = f.read().decode('utf-8', errors='replace')
        resultado = conexao.importar_vpn_saida(
            nome, conteudo, usuario, senha
        )
        return jsonify(resultado)
    except Exception as e:
        logger.error(f"api_vpn_importar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/conexao/vpn/listar')
@login_required
def api_vpn_listar():
    try:
        return jsonify({
            'sucesso': True,
            'vpns': conexao.listar_vpns_saida()
        })
    except Exception as e:
        logger.error(f"api_vpn_listar: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/conexao/vpn/remover', methods=['POST'])
@login_required
def api_vpn_remover():
    try:
        d = request.get_json()
        return jsonify(conexao.remover_vpn_saida(d.get('id', '')))
    except Exception as e:
        logger.error(f"api_vpn_remover: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


@app.route('/api/conexao/vpn/conectar', methods=['POST'])
@login_required
def api_vpn_conectar():
    try:
        d = request.get_json()
        return jsonify(conexao.conectar_vpn(d.get('id', '')))
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
            d.get('id', ''), d.get('portas', [])
        ))
    except Exception as e:
        logger.error(f"api_vpn_portas_saida: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


# ── VPN de acesso ao servidor ─────────────────────────────

@app.route('/api/conexao/vpn_acesso/configurar', methods=['POST'])
@login_required
def api_vpn_acesso_configurar():
    try:
        d = request.get_json()
        return jsonify(conexao.configurar_vpn_acesso(d))
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
        resultado = conexao.gerar_ovpn_acesso()
        if not resultado['sucesso']:
            return jsonify(resultado)
        return send_file(
            resultado['arquivo'],
            as_attachment=True,
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


# ── modo de conexão ───────────────────────────────────────

@app.route('/api/conexao/modo', methods=['POST'])
@login_required
def api_modo_conexao():
    try:
        d    = request.get_json()
        modo = d.get('modo', 'direto')
        vpn_id = d.get('vpn_id', None)
        return jsonify(conexao.aplicar_modo(modo, vpn_id))
    except Exception as e:
        logger.error(f"api_modo_conexao: {e}")
        return jsonify({'sucesso': False, 'erro': str(e)})


# ── utilidades ────────────────────────────────────────────

def _listar_interfaces():
    try:
        return conexao.listar_interfaces()
    except Exception as e:
        logger.error(f"_listar_interfaces: {e}")
        return []

# ══════════════════════════════════════════════════════════
# INICIALIZAÇÃO
# ══════════════════════════════════════════════════════════

def inicializar_sistema():
    """Inicializa módulos e regras padrão"""
    try:
        # SSL
        cert, key = garantir_ssl()

        # UFW
        firewall.inicializar()

        # Regra padrão: porta 2000 sistema
        firewall.garantir_regra_sistema()

        return cert, key
    except Exception as e:
        logger.error(f"inicializar_sistema: {e}")
        raise


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("❌ Execute como root: sudo python3 app.py")
        sys.exit(1)

    print("""
╔══════════════════════════════════════════════════════════╗
║              RRFS Servidores v1.0                        ║
║         Sistema de Segurança de Rede                     ║
╚══════════════════════════════════════════════════════════╝
    """)

    cert, key = inicializar_sistema()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    print(f"🔒 HTTPS ativo → https://0.0.0.0:2000")
    print(f"📋 Logs de erro → {LOG_FILE}")

    app.run(
        host='0.0.0.0',
        port=2000,
        ssl_context=ctx,
        debug=False,
        threaded=True
    )
