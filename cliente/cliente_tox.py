#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cliente_tox.py - RRFS Servidores - Cliente de Acesso Remoto via Tox
v3.5 - compatível com modulos/tox_remoto.py v3.3

v3.5.1: CORRIGIDO login do Cockpit (cookie SameSite=Strict não era
  enviado após o login -> voltava à tela de login). Agora o proxy
  reescreve para SameSite=Lax.

v3.5 (novidades):
  - NOVO (rota mais próxima): o servidor anuncia seus IPs de LAN; o
    cliente faz bootstrap direto neles e o Tox passa a usar UDP direto
    na LAN mesmo com internet. Longe da LAN nada muda. O cliente
    também anuncia a própria LAN ao servidor (mão dupla) e re-tenta
    enquanto estiver só via relay TCP.
  - NOVO: bootstrap otimizado por latência (nós/relays mais próximos).
  - NOVO: painel mostra o caminho (UDP direto / relay TCP).
  - Log de diagnóstico do proxy (logins, WebSockets, erros, lentidão).

v3.4 (novidades):
  - CORRIGIDO (KasmVNC no Firefox): "'clipboard-read' ... is not a valid
    value for enumeration PermissionName". O Firefox não conhece essa
    permissão e o KasmVNC aborta. O cliente agora injeta um pequeno
    script (/__rrfs_polyfill.js) nas páginas HTML e faz
    navigator.permissions.query() nunca estourar erro.
  - NOVO: WebSocket pelo proxy (KasmVNC, noVNC, terminais web...). O
    upgrade é repassado como túnel TCP cru pelo Tox.
  - NOVO: "porta externa". Serviços liberados pelo administrador abrem
    uma porta LOCAL (127.0.0.1:<porta>) neste computador; tudo que
    conectar nela (Winbox, RDP, VNC, SSH nativo...) é levado ao
    equipamento/serviço remoto pelo Tox.
    Exemplo MikroTik: Winbox -> Connect To: 127.0.0.1:8291

v3.3: sem corpo_fim em GET, abort em erro de upload/timeout, Content-
Length conferido, fragmentos só expiram sem progresso, HTTP/1.1.

Roda localmente na máquina do administrador, bandeja do sistema,
servindo um painel web em http://127.0.0.1:2100/.

- Proxy de serviços HTTP: http://s-<id>.localhost:2100/...
- Porta externa: 127.0.0.1:<porta_local> (definida no servidor)
- SSH: via WebSocket /ws/ssh + xterm.js no painel
- "Login": colar o ID Tox do servidor em /login faz o pareamento.
"""

import os
import re
import sys
import json
import time
import uuid
import base64
import queue
import struct
import ctypes
import socket
import logging
import secrets
import threading
import ctypes.util
import ipaddress
import subprocess
import urllib.request
from datetime import datetime

from flask import (Flask, request, Response, jsonify, redirect,
                    url_for, stream_with_context)

try:
    from flask_sock import Sock
    _TEM_WEBSOCKET = True
except Exception:
    _TEM_WEBSOCKET = False

# Bandeja: no KDE Plasma (principalmente Wayland) o backend correto é o
# AppIndicator/StatusNotifier. O backend "xorg" (XEmbed) só funciona em X11 e
# costuma desenhar o ícone borrado/esticado. Se PyGObject estiver disponível,
# usamos AppIndicator; senão deixamos o pystray escolher.
if sys.platform.startswith("linux") and not os.environ.get("PYSTRAY_BACKEND"):
    try:
        import gi
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
        except Exception:
            gi.require_version("AppIndicator3", "0.1")
        os.environ["PYSTRAY_BACKEND"] = "appindicator"
    except Exception:
        pass

try:
    import pystray
    from PIL import Image, ImageDraw
    _TEM_TRAY = True
except Exception:
    _TEM_TRAY = False


# ===========================================================================
# CONSTANTES (espelhando modulos/tox_remoto.py - NÃO mude sem mudar os dois)
# ===========================================================================

VERSAO = "3.5"
PORTA_LOCAL = 2100
DICA_REDE_INTERVALO = 12
BOOT_TIMEOUT_RTT = 1.5
BOOT_MAX_RELAYS_TCP = 8
BOOT_MAX_WORKERS = 24
_IFACES_IGNORAR = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap",
                   "wg", "zt", "tailscale", "cni", "flannel", "kube")

DIR_BASE = os.path.dirname(os.path.abspath(__file__))
DIR_DADOS = os.path.join(DIR_BASE, "dados_tox_cliente")
ARQ_CONFIG = os.path.join(DIR_DADOS, "config.json")
ARQ_SAVE_TOX = os.path.join(DIR_DADOS, "identidade.tox")
ARQ_NOS = os.path.join(DIR_DADOS, "nos_bootstrap.json")
ARQ_LOG = os.path.join(DIR_DADOS, "cliente_tox.log")
DIR_STATIC = os.path.join(DIR_BASE, "static")

os.makedirs(DIR_DADOS, mode=0o700, exist_ok=True)

TOX_ADDRESS_SIZE = 38
TOX_PUBLIC_KEY_SIZE = 32
TOX_SAVEDATA_TYPE_NONE = 0
TOX_SAVEDATA_TYPE_SAVE = 1

PACOTE_ID_DADOS = 160
MAX_FRAGMENTO = 1200
MAX_FRAGMENTOS_MSG = 4000
ERRO_SENDQ = 7
TIMEOUT_FRAGMENTOS = 600      # s SEM progresso

TAM_BLOCO_STREAM = 128 * 1024
TAM_BLOCO_TUNEL = 32 * 1024
TIMEOUT_ESPERAR_INICIO = 125
TIMEOUT_SEM_DADOS = 95
TIMEOUT_ABRIR_TUNEL = 25
LIMITE_INJECAO_HTML = 8 * 1024 * 1024

RE_ADDR = re.compile(r'^[0-9A-Fa-f]{76}$')
RE_HEX64 = re.compile(r'^[0-9A-Fa-f]{64}$')
RE_SUBDOMINIO = re.compile(r'^s-([A-Za-z0-9_-]+)\.localhost(?::\d+)?$',
                            re.IGNORECASE)

NOS_BOOTSTRAP_PADRAO = [
    {"ip": "node.tox.biribiri.org", "porta": 33445,
     "chave_publica": "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB6"},
    {"ip": "tox.initramfs.io", "porta": 33445,
     "chave_publica": "3F0A45A268367C1BEA652F258C85F4A66DA76BCEC757B14D2BC27D5DEE20C1A"},
    {"ip": "tox.abilinski.com", "porta": 33445,
     "chave_publica": "10C00EB250C3233E343E2AEBA07115A5C28920E9C8D29492F6D00B29049EDC7"},
    {"ip": "tox2.abilinski.com", "porta": 33445,
     "chave_publica": "7A6098B590BDC73F9723FC59F82B3F9085A64D1B213AAF8E610FD351930D052"},
]

# Script injetado nas páginas HTML dos serviços (corrige o erro do
# KasmVNC no Firefox: permissions.query({name:'clipboard-read'}) lança
# TypeError porque o Firefox não conhece esse nome de permissão).
POLYFILL_JS = r"""(function(){
try{
  var P=window.Permissions&&window.Permissions.prototype;
  if(!P||typeof P.query!=='function')return;
  var orig=P.query;
  P.query=function(d){
    var neg={state:'denied',onchange:null,name:(d&&d.name)||''};
    try{
      return Promise.resolve(orig.call(this,d)).catch(function(){return neg;});
    }catch(e){
      return Promise.resolve(neg);
    }
  };
}catch(e){}
})();
"""
TAG_POLYFILL = b'<script src="/__rrfs_polyfill.js"></script>'
RE_HEAD = re.compile(rb'<head(?:\s[^>]*)?>', re.IGNORECASE)
RE_HTML = re.compile(rb'<html(?:\s[^>]*)?>', re.IGNORECASE)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(ARQ_LOG, encoding="utf-8"),
              logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("cliente_tox")


def _ip_lan_valido(ip):
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.version != 4:
        return False
    if (a.is_loopback or a.is_link_local or a.is_multicast or
            a.is_unspecified or a.is_reserved):
        return False
    return a.is_private or a in ipaddress.ip_network("100.64.0.0/10")


def _ips_lan_locais():
    """IPv4 de LAN desta máquina (Linux, Windows e macOS)."""
    ips = []
    try:
        if os.name == "nt":
            for info in socket.getaddrinfo(socket.gethostname(), None,
                                           socket.AF_INET):
                ips.append(info[4][0])
        else:
            try:
                out = subprocess.run(
                    "ip -4 -o addr show scope global",
                    shell=True, capture_output=True, text=True,
                    timeout=5).stdout
                for l in out.splitlines():
                    p = l.split()
                    if len(p) >= 4 and not p[1].startswith(_IFACES_IGNORAR):
                        ips.append(p[3].split("/")[0])
            except Exception:
                pass
        # IP da rota padrão (funciona em qualquer SO)
        try:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.connect(("203.0.113.1", 9))
            ips.append(u.getsockname()[0])
            u.close()
        except Exception:
            pass
    except Exception:
        log.exception("ips_lan_locais")
    saida = []
    for ip in ips:
        if _ip_lan_valido(ip) and ip not in saida:
            saida.append(ip)
    return saida[:6]


def medir_latencia_nos(nos, timeout=BOOT_TIMEOUT_RTT):
    """(rtt_ms|None, nó) ordenado: menor latência primeiro."""
    resultados = {}
    lock = threading.Lock()
    fila = list(enumerate(nos))

    def trabalhador():
        while True:
            with lock:
                if not fila:
                    return
                i, no = fila.pop()
            rtt = None
            try:
                tcp = int((no.get("tcp_ports") or [no["porta"]])[0])
                t0 = time.time()
                c = socket.create_connection((no["ip"], tcp),
                                             timeout=timeout)
                rtt = (time.time() - t0) * 1000.0
                c.close()
            except Exception:
                rtt = None
            with lock:
                resultados[i] = rtt

    ths = [threading.Thread(target=trabalhador, daemon=True)
           for _ in range(min(BOOT_MAX_WORKERS, max(1, len(nos))))]
    for t in ths:
        t.start()
    for t in ths:
        t.join(timeout * 4 + 5)
    out = [(resultados.get(i), no) for i, no in enumerate(nos)]
    out.sort(key=lambda x: (x[0] is None, x[0] if x[0] is not None else 0))
    return out


class TransferenciaAbortada(Exception):
    """Transferência HTTP interrompida (erro, timeout, truncamento)."""


def _ajustar_set_cookie_cliente(valor):
    """O navegador acessa o serviço por http://s-<id>.localhost, vindo
    do painel (127.0.0.1): para ele isso é navegação ENTRE SITES, e
    cookies SameSite=Strict (ex.: login do Cockpit) deixam de ser
    enviados no GET / seguinte -> volta a tela de login. Lax é enviado
    em navegações de topo. Também remove Domain/Secure/None, que
    seriam rejeitados em http://localhost."""
    v = re.sub(r';\s*Domain=[^;]*', '', str(valor), flags=re.I)
    v = re.sub(r';\s*Secure\s*(?=;|$)', '', v, flags=re.I)
    v = re.sub(r'(;\s*SameSite=)(Strict|None)', r'\1Lax', v, flags=re.I)
    return v


def _injetar_polyfill(html):
    m = RE_HEAD.search(html)
    if m:
        return html[:m.end()] + TAG_POLYFILL + html[m.end():]
    m = RE_HTML.search(html)
    if m:
        return html[:m.end()] + TAG_POLYFILL + html[m.end():]
    return TAG_POLYFILL + html


# ===========================================================================
# BINDINGS CTYPES PARA LIBTOXCORE (idêntico ao servidor)
# ===========================================================================

_LIB = None


def carregar_libtoxcore():
    global _LIB
    if _LIB is not None:
        return _LIB
    nomes = ["libtoxcore.so", "libtoxcore.so.2",
             "libtoxcore.so.1", "libtoxcore.so.0"]
    caminho = ctypes.util.find_library("toxcore")
    if caminho:
        nomes.insert(0, caminho)
    erro_final = None
    for nome in nomes:
        try:
            _LIB = ctypes.CDLL(nome)
            _configurar_assinaturas(_LIB)
            return _LIB
        except (OSError, AttributeError) as e:
            _LIB = None
            erro_final = e
    raise RuntimeError(f"libtoxcore não encontrada/compatível: {erro_final}")


def _configurar_assinaturas(lib):
    vp, ci = ctypes.c_void_p, ctypes.c_int
    u8p = ctypes.POINTER(ctypes.c_uint8)
    u32, u16 = ctypes.c_uint32, ctypes.c_uint16
    st, cb, cp = ctypes.c_size_t, ctypes.c_bool, ctypes.c_char_p
    eri = ctypes.POINTER(ci)

    def fn(nome, restype, argtypes):
        f = getattr(lib, nome)
        f.restype, f.argtypes = restype, argtypes

    fn('tox_options_new', vp, [eri])
    fn('tox_options_free', None, [vp])
    fn('tox_options_set_ipv6_enabled', None, [vp, cb])
    fn('tox_options_set_udp_enabled', None, [vp, cb])
    fn('tox_options_set_local_discovery_enabled', None, [vp, cb])
    fn('tox_options_set_savedata_type', None, [vp, ci])
    fn('tox_options_set_savedata_data', None, [vp, u8p, st])
    fn('tox_new', vp, [vp, eri])
    fn('tox_kill', None, [vp])
    fn('tox_bootstrap', cb, [vp, cp, u16, u8p, eri])
    fn('tox_add_tcp_relay', cb, [vp, cp, u16, u8p, eri])
    fn('tox_iteration_interval', u32, [vp])
    fn('tox_iterate', None, [vp, vp])
    fn('tox_self_get_address', None, [vp, u8p])
    fn('tox_self_get_connection_status', ci, [vp])
    fn('tox_get_savedata_size', st, [vp])
    fn('tox_get_savedata', None, [vp, u8p])
    fn('tox_friend_add', u32, [vp, u8p, u8p, st, eri])
    fn('tox_friend_delete', cb, [vp, u32, eri])
    fn('tox_friend_get_public_key', cb, [vp, u32, u8p, eri])
    fn('tox_friend_send_lossless_packet', cb, [vp, u32, u8p, st, eri])
    fn('tox_self_get_friend_list_size', st, [vp])
    fn('tox_self_get_friend_list', None, [vp, ctypes.POINTER(u32)])
    fn('tox_callback_self_connection_status', None, [vp, vp])
    fn('tox_callback_friend_request', None, [vp, vp])
    fn('tox_callback_friend_connection_status', None, [vp, vp])
    fn('tox_callback_friend_lossless_packet', None, [vp, vp])

    for nome, rt, at in (
            ('tox_self_get_dht_id', None, [vp, u8p]),
            ('tox_self_get_udp_port', u16, [vp, eri])):
        try:
            f = getattr(lib, nome)
            f.restype, f.argtypes = rt, at
        except AttributeError:
            log.warning("libtoxcore sem %s: rota LAN limitada", nome)


# ===========================================================================
# _NoTox
# ===========================================================================

class _NoTox:

    def __init__(self, caminho_savedata, log_fn=None):
        self.lib = carregar_libtoxcore()
        self.caminho = caminho_savedata
        self.log = log_fn or (lambda msg: log.info(msg))
        self.tox = None
        self._rodando = False
        self._trava = threading.RLock()
        self._amigos = {}
        self._frag = {}
        self._refs = []

        self._fila_msgs = queue.Queue()

        self.cb_msg = None
        self.cb_status_rede = None
        self.cb_status_amigo = None

        self._criar_tox()

    def _criar_tox(self):
        with self._trava:
            erro = ctypes.c_int(0)
            op = self.lib.tox_options_new(ctypes.byref(erro))
            if not op:
                raise RuntimeError("Falha ao criar Tox_Options")
            self.lib.tox_options_set_ipv6_enabled(op, True)
            self.lib.tox_options_set_udp_enabled(op, True)
            self.lib.tox_options_set_local_discovery_enabled(op, True)

            buf_save = None
            if os.path.exists(self.caminho):
                with open(self.caminho, 'rb') as f:
                    dados = f.read()
                if dados:
                    self.lib.tox_options_set_savedata_type(op, TOX_SAVEDATA_TYPE_SAVE)
                    buf_save = (ctypes.c_uint8 * len(dados)).from_buffer_copy(dados)
                    self.lib.tox_options_set_savedata_data(op, buf_save, len(dados))
            if buf_save is None:
                self.lib.tox_options_set_savedata_type(op, TOX_SAVEDATA_TYPE_NONE)

            e2 = ctypes.c_int(0)
            self.tox = self.lib.tox_new(op, ctypes.byref(e2))
            self.lib.tox_options_free(op)
            if not self.tox:
                raise RuntimeError(f"Falha ao criar instância Tox (código {e2.value})")
            self._registrar_callbacks()
            self._carregar_amigos()
            self._salvar_sem_trava()
        self.log(f"Identidade pronta: {self.endereco_hex()[:16]}...")

    def _registrar_callbacks(self):
        vp = ctypes.c_void_p
        u8p = ctypes.POINTER(ctypes.c_uint8)
        CB_SELF = ctypes.CFUNCTYPE(None, vp, ctypes.c_int, vp)
        CB_REQ = ctypes.CFUNCTYPE(None, vp, u8p, u8p, ctypes.c_size_t, vp)
        CB_CONN = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, ctypes.c_int, vp)
        CB_PKT = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, u8p, ctypes.c_size_t, vp)

        def ao_rede(tox, status, ud):
            nomes = {0: 'Offline', 1: 'Conectado (TCP)', 2: 'Conectado (UDP)'}
            self.log(f"Rede Tox: {nomes.get(status, status)}")
            if self.cb_status_rede:
                try:
                    self.cb_status_rede(status)
                except Exception:
                    log.exception("cb_status_rede")

        def ao_pedido(tox, chave_ptr, msg_ptr, tam, ud):
            try:
                chave = bytes(ctypes.cast(
                    chave_ptr, ctypes.POINTER(ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)
                ).contents).hex().upper()
                self.log(f"Pedido de amizade recebido e ignorado: {chave[:16]}...")
            except Exception:
                pass

        def ao_amigo(tox, numero, status, ud):
            self._amigos.setdefault(numero, {})['status'] = status
            if self.cb_status_amigo:
                try:
                    self.cb_status_amigo(numero, status)
                except Exception:
                    log.exception("cb_status_amigo")

        def ao_pacote(tox, numero, dados_ptr, tam, ud):
            try:
                bruto = bytes(ctypes.cast(
                    dados_ptr, ctypes.POINTER(ctypes.c_uint8 * tam)
                ).contents)
            except Exception:
                return
            self._fragmento(numero, bruto)

        self._c1, self._c2, self._c3, self._c4 = (
            CB_SELF(ao_rede), CB_REQ(ao_pedido),
            CB_CONN(ao_amigo), CB_PKT(ao_pacote)
        )
        self._refs = [self._c1, self._c2, self._c3, self._c4]

        L = self.lib
        L.tox_callback_self_connection_status(self.tox, self._c1)
        L.tox_callback_friend_request(self.tox, self._c2)
        L.tox_callback_friend_connection_status(self.tox, self._c3)
        L.tox_callback_friend_lossless_packet(self.tox, self._c4)

    def _carregar_amigos(self):
        tam = self.lib.tox_self_get_friend_list_size(self.tox)
        if tam == 0:
            return
        buf = (ctypes.c_uint32 * tam)()
        self.lib.tox_self_get_friend_list(self.tox, buf)
        for numero in buf:
            e = ctypes.c_int(0)
            kb = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)()
            ok = self.lib.tox_friend_get_public_key(self.tox, numero, kb, ctypes.byref(e))
            self._amigos[numero] = {
                'chave_publica': bytes(kb).hex().upper() if ok else '',
                'status': 0
            }

    def _fragmento(self, numero, bruto):
        if len(bruto) < 9 or bruto[0] != PACOTE_ID_DADOS:
            return
        frame_id = bruto[1:5]
        idx = struct.unpack('>H', bruto[5:7])[0]
        total = struct.unpack('>H', bruto[7:9])[0]
        if total < 1 or total > MAX_FRAGMENTOS_MSG or idx >= total:
            return
        k = (numero, frame_id)
        reg = self._frag.setdefault(k, {'t': time.time(), 'total': total, 'partes': {}})
        if reg['total'] != total:
            self._frag.pop(k, None)
            return
        reg['t'] = time.time()     # renova a cada fragmento
        reg['partes'][idx] = bruto[9:]
        if len(reg['partes']) < total:
            return
        completo = b''.join(reg['partes'][i] for i in range(total))
        self._frag.pop(k, None)
        try:
            msg = json.loads(completo.decode('utf-8'))
        except Exception:
            return
        self._fila_msgs.put((numero, msg))

    def _limpar_fragmentos(self):
        agora = time.time()
        for k in [k for k, v in self._frag.items() if agora - v['t'] > TIMEOUT_FRAGMENTOS]:
            self._frag.pop(k, None)

    def enviar(self, numero, mensagem):
        """Envia mensagem completa (fragmentada). Fila cheia = espera
        enquanto o servidor estiver conectado; só levanta exceção se
        ele desconectar ou o Tox parar."""
        if self._amigos.get(numero, {}).get('status', 0) == 0:
            raise RuntimeError('Amigo desconectado')
        bruto = json.dumps(mensagem, ensure_ascii=False).encode('utf-8')
        fid = secrets.token_bytes(4)
        total = max(1, -(-len(bruto) // MAX_FRAGMENTO))
        if total > MAX_FRAGMENTOS_MSG:
            raise RuntimeError('Mensagem grande demais')
        for idx in range(total):
            pedaco = bruto[idx * MAX_FRAGMENTO:(idx + 1) * MAX_FRAGMENTO]
            pkt = (bytes([PACOTE_ID_DADOS]) + fid +
                   struct.pack('>H', idx) + struct.pack('>H', total) + pedaco)
            buf = (ctypes.c_uint8 * len(pkt)).from_buffer_copy(pkt)
            tentativas = 0
            while True:
                erro = ctypes.c_int(0)
                with self._trava:
                    if not self.tox:
                        raise RuntimeError('Tox parado')
                    ok = self.lib.tox_friend_send_lossless_packet(
                        self.tox, numero, buf, len(pkt), ctypes.byref(erro))
                if ok:
                    break
                if erro.value == ERRO_SENDQ:
                    if self._amigos.get(numero, {}).get('status', 0) == 0:
                        raise RuntimeError('Servidor desconectou durante o envio')
                    tentativas += 1
                    time.sleep(min(0.05 * (1 + tentativas // 10), 0.5))
                    continue
                raise RuntimeError(f'Falha ao enviar pacote Tox (código {erro.value})')

    def _salvar_sem_trava(self):
        if not self.tox:
            return
        tam = self.lib.tox_get_savedata_size(self.tox)
        buf = (ctypes.c_uint8 * tam)()
        self.lib.tox_get_savedata(self.tox, buf)
        tmp = self.caminho + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(bytes(buf))
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.caminho)

    def salvar(self):
        with self._trava:
            self._salvar_sem_trava()

    def endereco_hex(self):
        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE)()
        with self._trava:
            if not self.tox:
                return ''
            self.lib.tox_self_get_address(self.tox, buf)
        return bytes(buf).hex().upper()

    def status_rede(self):
        with self._trava:
            if not self.tox:
                return 0
            return self.lib.tox_self_get_connection_status(self.tox)

    def status_conexao_amigo(self, numero):
        return self._amigos.get(numero, {}).get('status', 0) != 0

    def buscar_amigo_por_chave(self, pubkey_hex):
        pubkey_hex = pubkey_hex.upper()
        for numero, info in self._amigos.items():
            if info.get('chave_publica', '').upper() == pubkey_hex:
                return numero
        return None

    def adicionar_amigo_por_endereco(self, endereco_hex):
        endereco_hex = endereco_hex.strip().upper()
        bruto = bytes.fromhex(endereco_hex)
        if len(bruto) != TOX_ADDRESS_SIZE:
            raise ValueError('Endereço Tox com tamanho inválido')
        pubkey_hex = bruto[:TOX_PUBLIC_KEY_SIZE].hex().upper()

        existente = self.buscar_amigo_por_chave(pubkey_hex)
        if existente is not None:
            return existente

        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE).from_buffer_copy(bruto)
        msg = "RRFS Cliente - pedido de pareamento".encode('utf-8')
        mb = (ctypes.c_uint8 * len(msg)).from_buffer_copy(msg)
        erro = ctypes.c_int(0)
        with self._trava:
            numero = self.lib.tox_friend_add(self.tox, buf, mb, len(msg), ctypes.byref(erro))
        if erro.value != 0:
            raise RuntimeError(f'Falha ao adicionar servidor (código tox {erro.value})')
        self._amigos[numero] = {'chave_publica': pubkey_hex, 'status': 0}
        self.salvar()
        return numero

    def remover_amigo(self, numero):
        erro = ctypes.c_int(0)
        with self._trava:
            if self.tox:
                self.lib.tox_friend_delete(self.tox, numero, ctypes.byref(erro))
        self._amigos.pop(numero, None)
        self.salvar()

    def bootstrap(self, nos):
        ok_total = 0
        for no in nos:
            try:
                chave = bytes.fromhex(no['chave_publica'])
                if len(chave) != TOX_PUBLIC_KEY_SIZE:
                    continue
                buf = (ctypes.c_uint8 * len(chave)).from_buffer_copy(chave)
                host = no['ip'].encode()
                with self._trava:
                    if not self.tox:
                        return ok_total
                    e = ctypes.c_int(0)
                    if self.lib.tox_bootstrap(self.tox, host, int(no['porta']), buf, ctypes.byref(e)):
                        ok_total += 1
                    tcp = int((no.get('tcp_ports') or [no['porta']])[0])
                    e2 = ctypes.c_int(0)
                    self.lib.tox_add_tcp_relay(self.tox, host, tcp, buf, ctypes.byref(e2))
            except Exception as ex:
                log.error(f"bootstrap {no.get('ip')}: {ex}")
        return ok_total

    def bootstrap_otimizado(self, nos):
        if not nos:
            return 0
        medidos = medir_latencia_nos(nos)
        vivos = [(r, n) for r, n in medidos if r is not None]
        relays = set(id(n) for _, n in vivos[:BOOT_MAX_RELAYS_TCP])
        ok_total = 0
        for r, no in medidos:
            try:
                chave = bytes.fromhex(no['chave_publica'])
                if len(chave) != TOX_PUBLIC_KEY_SIZE:
                    continue
                buf = (ctypes.c_uint8 * len(chave)).from_buffer_copy(chave)
                host = no['ip'].encode()
                with self._trava:
                    if not self.tox:
                        return ok_total
                    e = ctypes.c_int(0)
                    if self.lib.tox_bootstrap(self.tox, host, int(no['porta']),
                                              buf, ctypes.byref(e)):
                        ok_total += 1
                    if not vivos or id(no) in relays:
                        tcp = int((no.get('tcp_ports') or [no['porta']])[0])
                        e2 = ctypes.c_int(0)
                        self.lib.tox_add_tcp_relay(self.tox, host, tcp, buf,
                                                   ctypes.byref(e2))
            except Exception as ex:
                log.error(f"bootstrap_otimizado {no.get('ip')}: {ex}")
        if vivos:
            log.info("Bootstrap otimizado: mais próximo %s (%.0f ms), %d/%d "
                     "nós respondem", vivos[0][1]['ip'], vivos[0][0],
                     len(vivos), len(nos))
        return ok_total

    def dht_id_hex(self):
        try:
            buf = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)()
            with self._trava:
                if not self.tox:
                    return ''
                self.lib.tox_self_get_dht_id(self.tox, buf)
            return bytes(buf).hex().upper()
        except AttributeError:
            return ''

    def porta_udp(self):
        try:
            e = ctypes.c_int(0)
            with self._trava:
                if not self.tox:
                    return 0
                return int(self.lib.tox_self_get_udp_port(self.tox,
                                                          ctypes.byref(e)))
        except AttributeError:
            return 0

    def aplicar_dica_lan(self, ips, porta, dht_hex):
        try:
            chave = bytes.fromhex(dht_hex)
            if len(chave) != TOX_PUBLIC_KEY_SIZE:
                return 0
            porta = int(porta)
            if not 1024 <= porta <= 65535:
                return 0
        except (ValueError, TypeError):
            return 0
        n = 0
        for ip in ips[:6]:
            if not _ip_lan_valido(ip):
                continue
            try:
                buf = (ctypes.c_uint8 * len(chave)).from_buffer_copy(chave)
                e = ctypes.c_int(0)
                with self._trava:
                    if not self.tox:
                        return n
                    if self.lib.tox_bootstrap(self.tox, str(ip).encode(),
                                              porta, buf, ctypes.byref(e)):
                        n += 1
            except Exception:
                log.exception("aplicar_dica_lan")
        return n

    def status_amigo(self, numero):
        return self._amigos.get(numero, {}).get('status', 0)

    def iniciar_loop(self):
        self._rodando = True
        threading.Thread(target=self._loop, name="Tox-Loop", daemon=True).start()
        threading.Thread(target=self._loop_salvar, name="Tox-Save", daemon=True).start()
        threading.Thread(target=self._loop_mensagens, name="Tox-Dispatch", daemon=True).start()

    def _loop(self):
        ult_limpeza = time.time()
        while self._rodando:
            with self._trava:
                if not self._rodando or not self.tox:
                    break
                self.lib.tox_iterate(self.tox, None)
                intervalo = self.lib.tox_iteration_interval(self.tox)
            if time.time() - ult_limpeza > 15:
                self._limpar_fragmentos()
                ult_limpeza = time.time()
            time.sleep(max(intervalo, 10) / 1000.0)

    def _loop_salvar(self):
        while self._rodando:
            for _ in range(20):
                if not self._rodando:
                    return
                time.sleep(1)
            try:
                self.salvar()
            except Exception:
                log.exception("salvar periódico")

    def _loop_mensagens(self):
        while self._rodando:
            try:
                numero, msg = self._fila_msgs.get(timeout=0.5)
            except queue.Empty:
                continue
            if self.cb_msg:
                try:
                    self.cb_msg(numero, msg)
                except Exception:
                    log.exception(f"erro processando mensagem {msg.get('tipo')}")

    def parar(self):
        self._rodando = False
        time.sleep(0.3)
        with self._trava:
            if self.tox:
                try:
                    self._salvar_sem_trava()
                except Exception:
                    pass
                self.lib.tox_kill(self.tox)
                self.tox = None


# ===========================================================================
# CONFIGURAÇÃO DO CLIENTE
# ===========================================================================

class ConfigCliente:
    PADRAO = {
        "tox_id_servidor": "",
        "numero_amigo_servidor": None,
    }

    def __init__(self, caminho):
        self.caminho = caminho
        self.dados = dict(self.PADRAO)
        self.carregar()

    def carregar(self):
        if os.path.exists(self.caminho):
            try:
                with open(self.caminho, "r", encoding="utf-8") as f:
                    self.dados.update(json.load(f))
            except Exception:
                log.exception("Erro ao carregar config")
        else:
            self.salvar()

    def salvar(self):
        tmp = self.caminho + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.dados, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.caminho)

    def __getitem__(self, k):
        return self.dados.get(k)

    def __setitem__(self, k, v):
        self.dados[k] = v
        self.salvar()


# ===========================================================================
# BOOTSTRAP
# ===========================================================================

def _carregar_nos():
    try:
        if os.path.exists(ARQ_NOS):
            with open(ARQ_NOS, 'r', encoding='utf-8') as f:
                nos = json.load(f)
            nos_validos = [n for n in nos
                           if RE_HEX64.match(n.get('chave_publica', ''))]
            if nos_validos:
                return nos_validos
    except Exception:
        log.exception("carregar_nos")

    padrao_validos = [n for n in NOS_BOOTSTRAP_PADRAO
                       if RE_HEX64.match(n.get('chave_publica', ''))]
    invalidos = len(NOS_BOOTSTRAP_PADRAO) - len(padrao_validos)
    if invalidos:
        log.warning(
            "Lista de bootstrap padrão tem %d/%d chave(s) pública(s) "
            "inválida(s) (ignoradas). A descoberta local (LAN) e a "
            "atualização online (⬇ Nós Tox) continuam disponíveis.",
            invalidos, len(NOS_BOOTSTRAP_PADRAO)
        )
    return padrao_validos


def _salvar_nos(nos):
    try:
        with open(ARQ_NOS, 'w', encoding='utf-8') as f:
            json.dump(nos, f, indent=2, ensure_ascii=False)
    except Exception:
        log.exception("salvar_nos")


def _atualizar_nos_online():
    try:
        req = urllib.request.Request('https://nodes.tox.chat/json',
                                      headers={'User-Agent': 'RRFS-Cliente'})
        with urllib.request.urlopen(req, timeout=10) as r:
            dados = json.loads(r.read().decode('utf-8'))
        atuais = _carregar_nos()
        existentes = {(n['ip'], int(n['porta'])) for n in atuais}
        novos = 0
        for it in dados.get('nodes', []):
            ip = it.get('ipv4')
            chave = (it.get('public_key') or '').upper()
            if not it.get('status_udp') or not ip or ip == '-' or not RE_HEX64.match(chave):
                continue
            porta = int(it.get('port', 33445))
            if (ip, porta) in existentes:
                continue
            atuais.append({'ip': ip, 'porta': porta, 'chave_publica': chave,
                            'tcp_ports': it.get('tcp_ports') or []})
            existentes.add((ip, porta))
            novos += 1
        _salvar_nos(atuais)
        return True, novos
    except Exception as e:
        log.warning(f"Sem acesso à lista de nós online: {e}")
        return False, 0


# ===========================================================================
# GERENCIADOR DE REQUISIÇÕES HTTP (protocolo streaming)
# ===========================================================================

class RequisicaoPendente:
    def __init__(self, req_id):
        self.req_id = req_id
        self.fila_eventos = queue.Queue()


class GerenciadorRequisicoes:

    HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate",
                  "proxy-authorization", "te", "trailers",
                  "transfer-encoding", "upgrade", "host",
                  "content-length", "expect"}

    def __init__(self, notox, obter_numero_amigo):
        self.notox = notox
        self.obter_numero_amigo = obter_numero_amigo
        self._pendentes = {}
        self._lock = threading.RLock()

    def tratar_mensagem(self, numero, msg):
        tipo = msg.get("tipo")
        req_id = msg.get("id")
        if not req_id:
            return
        with self._lock:
            pend = self._pendentes.get(req_id)
        if pend is None:
            return

        if tipo == "http_resposta_inicio":
            pend.fila_eventos.put(("inicio", msg.get("status", 502), msg.get("headers", [])))
        elif tipo == "http_resposta_dados":
            try:
                dados = base64.b64decode(msg.get("dados", ""))
            except Exception:
                pend.fila_eventos.put(("erro", "bloco de dados inválido"))
                return
            pend.fila_eventos.put(("dados", dados))
        elif tipo == "http_resposta_fim":
            pend.fila_eventos.put(("fim", None))
        elif tipo == "http_resposta_erro":
            pend.fila_eventos.put(("erro", msg.get("mensagem", "erro desconhecido")))

    def _limpar(self, req_id):
        with self._lock:
            self._pendentes.pop(req_id, None)

    def _cancelar_no_servidor(self, numero_amigo, req_id):
        try:
            self.notox.enviar(numero_amigo, {"tipo": "http_cancelar", "id": req_id})
        except Exception:
            pass

    def encaminhar(self, service_id, method, path, headers, stream_entrada, tamanho_entrada):
        numero_amigo = self.obter_numero_amigo()
        if numero_amigo is None or not self.notox.status_conexao_amigo(numero_amigo):
            return Response("Servidor remoto não está conectado no momento (Tox offline).",
                             status=503, mimetype="text/plain")

        _t_inicio = time.time()
        if "/cockpit" in path or path == "/":
            _ck = ""
            for _k, _v in headers.items():
                if _k.lower() == "cookie":
                    _ck = _v
            _nomes = [c.split("=", 1)[0].strip() for c in _ck.split(";") if c.strip()]
            log.info("COOKIE-DIAG pedido %s %s: cookies enviados pelo navegador=%s "
                     "| Authorization=%s", method, path.split("?", 1)[0],
                     _nomes or "NENHUM",
                     any(k.lower() == "authorization" for k in headers))
        req_id = uuid.uuid4().hex
        pend = RequisicaoPendente(req_id)
        with self._lock:
            self._pendentes[req_id] = pend

        # Navegação (página HTML): pede o conteúdo SEM compressão para
        # podermos injetar o polyfill. Arquivos/scripts/imagens continuam
        # comprimidos normalmente.
        accept = ""
        for k, v in headers.items():
            if k.lower() == "accept":
                accept = v
                break
        navegacao = "text/html" in accept.lower()

        headers_envio = {k: v for k, v in headers.items()
                         if k.lower() not in self.HOP_BY_HOP and
                         not (navegacao and k.lower() == "accept-encoding")}
        if navegacao:
            headers_envio["Accept-Encoding"] = "identity"
        tem_corpo = bool(tamanho_entrada and tamanho_entrada > 0) or method.upper() in ("POST", "PUT", "PATCH")

        try:
            self.notox.enviar(numero_amigo, {
                "tipo": "http_abrir", "id": req_id, "service_id": service_id,
                "method": method, "path": path, "headers": headers_envio,
                "tem_corpo": tem_corpo,
            })
        except Exception as e:
            self._limpar(req_id)
            return Response(f"Falha ao enviar requisição via Tox: {e}", status=502, mimetype="text/plain")

        # Sem corpo: NÃO enviar http_corpo_fim (o servidor já iniciou
        # a requisição; enviar fim faria processá-la duas vezes).
        if tem_corpo and stream_entrada is not None:
            def _enviar_corpo():
                try:
                    while True:
                        bloco = stream_entrada.read(TAM_BLOCO_STREAM)
                        if not bloco:
                            break
                        self.notox.enviar(numero_amigo, {
                            "tipo": "http_corpo", "id": req_id,
                            "dados": base64.b64encode(bloco).decode("ascii"),
                        })
                    self.notox.enviar(numero_amigo, {"tipo": "http_corpo_fim", "id": req_id})
                except Exception as e:
                    # Upload incompleto: cancela (nunca finalizar).
                    log.warning(f"Falha ao enviar corpo da requisicao {req_id}: {e}")
                    pend.fila_eventos.put(("erro", f"falha ao enviar corpo: {e}"))
                    self._cancelar_no_servidor(numero_amigo, req_id)
            threading.Thread(target=_enviar_corpo, daemon=True).start()
        elif tem_corpo:
            # método com corpo mas sem stream: fecha o corpo vazio
            try:
                self.notox.enviar(numero_amigo, {"tipo": "http_corpo_fim", "id": req_id})
            except Exception:
                pass

        try:
            evento = pend.fila_eventos.get(timeout=TIMEOUT_ESPERAR_INICIO)
        except queue.Empty:
            self._limpar(req_id)
            self._cancelar_no_servidor(numero_amigo, req_id)
            return Response("Tempo esgotado esperando resposta do servidor remoto.",
                             status=504, mimetype="text/plain")

        tipo_evento = evento[0]
        if tipo_evento == "erro":
            self._limpar(req_id)
            return Response(f"Erro no servidor remoto: {evento[1]}", status=502, mimetype="text/plain")
        if tipo_evento != "inicio":
            self._limpar(req_id)
            return Response("Resposta inesperada do servidor remoto.", status=502, mimetype="text/plain")

        status = evento[1]
        headers_resp = evento[2] or []
        _cam = path.split("?", 1)[0]
        if status >= 400 or _cam.endswith("/login"):
            log.info("proxy %s %s -> %s (%.1fs)", method, _cam, status,
                     time.time() - _t_inicio)
        elif time.time() - _t_inicio > 5:
            log.info("proxy LENTO %s %s (%.1fs até o 1º byte)", method,
                     _cam, time.time() - _t_inicio)

        if isinstance(headers_resp, dict):
            pares_headers = list(headers_resp.items())
        else:
            pares_headers = [(h[0], h[1]) for h in headers_resp
                              if isinstance(h, (list, tuple)) and len(h) >= 2]

        for _k, _v in pares_headers:
            if _k.lower() == "set-cookie":
                _p = [x.strip() for x in str(_v).split(";")]
                log.info("COOKIE-DIAG resposta %s %s -> %s: Set-Cookie nome=%s "
                         "atributos=%s (valor omitido, %d chars)", method,
                         path.split("?", 1)[0], status,
                         _p[0].split("=", 1)[0], _p[1:],
                         len(_p[0].split("=", 1)[-1]))

        # Content-Length preservado e conferido no fim do stream.
        esperado = None
        ctype = ""
        cenc = ""
        for k, v in pares_headers:
            kl = k.lower()
            if kl == "content-length":
                try:
                    esperado = int(v)
                except ValueError:
                    pass
            elif kl == "content-type":
                ctype = str(v)
            elif kl == "content-encoding":
                cenc = str(v)
        sem_corpo_resp = (method.upper() == "HEAD" or status in (204, 304)
                          or 100 <= status < 200)
        if sem_corpo_resp:
            esperado = None

        # Injeta o polyfill só em HTML sem compressão
        injetar = (navegacao and not sem_corpo_resp and
                   "text/html" in ctype.lower() and not cenc.strip())

        def _gerador():
            recebidos = 0
            buf, tam_buf = [], 0
            bufferizando = injetar
            try:
                while True:
                    try:
                        ev = pend.fila_eventos.get(timeout=TIMEOUT_SEM_DADOS)
                    except queue.Empty:
                        raise TransferenciaAbortada("timeout sem dados do servidor")
                    if ev[0] == "dados":
                        recebidos += len(ev[1])
                        if bufferizando:
                            buf.append(ev[1])
                            tam_buf += len(ev[1])
                            if tam_buf > LIMITE_INJECAO_HTML:
                                # HTML gigante: desiste de injetar
                                bufferizando = False
                                yield b"".join(buf)
                                buf = []
                        else:
                            yield ev[1]
                    elif ev[0] == "fim":
                        if esperado is not None and recebidos != esperado:
                            raise TransferenciaAbortada(
                                f"resposta incompleta ({recebidos}/{esperado} bytes)")
                        if bufferizando:
                            yield _injetar_polyfill(b"".join(buf))
                        break
                    elif ev[0] == "erro":
                        raise TransferenciaAbortada(str(ev[1]))
            except GeneratorExit:
                self._cancelar_no_servidor(numero_amigo, req_id)
                raise
            except TransferenciaAbortada as e:
                # Re-levanta: o navegador vê a conexão cair (download
                # falho) em vez de receber um arquivo truncado como se
                # estivesse completo.
                log.warning(f"Transferência {req_id} abortada: {e}")
                self._cancelar_no_servidor(numero_amigo, req_id)
                raise
            finally:
                self._limpar(req_id)

        # lista de tuplas (preserva cabeçalhos repetidos, ex.: Set-Cookie)
        # Com injeção, o tamanho muda: sem Content-Length (vai chunked).
        omitir = {"transfer-encoding", "connection"}
        if injetar:
            omitir.add("content-length")
        headers_final = [
            (k, _ajustar_set_cookie_cliente(v) if k.lower() == "set-cookie" else v)
            for k, v in pares_headers if k.lower() not in omitir]
        return Response(stream_with_context(_gerador()), status=status, headers=headers_final)

    def ao_amigo_desconectar(self, numero):
        with self._lock:
            pendentes = list(self._pendentes.values())
        for pend in pendentes:
            pend.fila_eventos.put(("erro", "amigo desconectado"))


# ===========================================================================
# TÚNEIS TCP (WebSocket + porta externa)
# ===========================================================================

class GerenciadorTuneis:
    """Túnel TCP cru pelo Tox.
    tcp_abrir -> tcp_aberto | tcp_erro; depois tcp_dados / tcp_fechar."""

    def __init__(self, notox, obter_numero_amigo):
        self.notox = notox
        self.obter_numero = obter_numero_amigo
        self._filas = {}
        self._lock = threading.Lock()

    def tratar(self, msg):
        tid = msg.get("id")
        with self._lock:
            fila = self._filas.get(tid)
        if fila is not None:
            fila.put(msg)

    def ao_amigo_desconectar(self):
        with self._lock:
            filas = list(self._filas.values())
        for f in filas:
            f.put({"tipo": "tcp_erro", "mensagem": "servidor desconectou"})

    def _remover(self, tid):
        with self._lock:
            self._filas.pop(tid, None)

    def abrir(self, service_id, modo, extra=None, espera=TIMEOUT_ABRIR_TUNEL):
        """Retorna (True, (tid, fila)) ou (False, mensagem_de_erro)."""
        numero = self.obter_numero()
        if numero is None or not self.notox.status_conexao_amigo(numero):
            return False, "Servidor remoto offline (Tox)"
        tid = uuid.uuid4().hex
        fila = queue.Queue()
        with self._lock:
            self._filas[tid] = fila
        msg = {"tipo": "tcp_abrir", "id": tid,
               "service_id": service_id, "modo": modo}
        if extra:
            msg.update(extra)
        try:
            self.notox.enviar(numero, msg)
        except Exception as e:
            self._remover(tid)
            return False, f"Falha ao enviar pedido de túnel: {e}"
        try:
            ev = fila.get(timeout=espera)
        except queue.Empty:
            try:
                self.notox.enviar(numero, {"tipo": "tcp_fechar", "id": tid})
            except Exception:
                pass
            self._remover(tid)
            return False, "Tempo esgotado abrindo o túnel"
        if ev.get("tipo") != "tcp_aberto":
            self._remover(tid)
            return False, ev.get("mensagem") or "Servidor recusou o túnel"
        return True, (tid, fila)

    def bombear(self, sock, tid, fila, numero):
        """Liga o socket local ao túnel (bloqueia até terminar)."""
        parar = threading.Event()

        def ler_socket():
            try:
                while not parar.is_set():
                    d = sock.recv(TAM_BLOCO_TUNEL)
                    if not d:
                        break
                    self.notox.enviar(numero, {
                        "tipo": "tcp_dados", "id": tid,
                        "dados": base64.b64encode(d).decode("ascii")})
            except Exception:
                pass
            finally:
                parar.set()
                fila.put({"tipo": "tcp_fechar_local"})

        threading.Thread(target=ler_socket, daemon=True,
                         name="Tunel-Ler").start()
        try:
            while not parar.is_set():
                try:
                    m = fila.get(timeout=1)
                except queue.Empty:
                    continue
                t = m.get("tipo")
                if t == "tcp_dados":
                    sock.sendall(base64.b64decode(m.get("dados", "")))
                elif t in ("tcp_fechar", "tcp_erro", "tcp_fechar_local"):
                    break
        except Exception:
            pass
        finally:
            parar.set()
            try:
                self.notox.enviar(numero, {"tipo": "tcp_fechar", "id": tid})
            except Exception:
                pass
            for fn in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
                try:
                    fn()
                except Exception:
                    pass
            self._remover(tid)


class ListenerPorta:
    """Porta local (127.0.0.1) que leva ao serviço remoto liberado."""

    def __init__(self, service_id, porta, tuneis, obter_numero, notox):
        self.sid = service_id
        self.porta = porta
        self.tuneis = tuneis
        self.obter_numero = obter_numero
        self.notox = notox
        self.ok = False
        self.erro = ""
        self._parar = threading.Event()
        self._srv = None

    def iniciar(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if os.name != "nt":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", self.porta))
            s.listen(16)
            s.settimeout(1.0)
            self._srv = s
            self.ok = True
            self.erro = ""
            log.info("Porta local 127.0.0.1:%d aberta (serviço %s)",
                     self.porta, self.sid)
        except OSError as e:
            self.ok = False
            self.erro = f"Porta local {self.porta} indisponível: {e}"
            log.warning(self.erro)
            return
        threading.Thread(target=self._aceitar, daemon=True,
                         name=f"Porta-{self.porta}").start()

    def _aceitar(self):
        while not self._parar.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._atender, args=(conn,),
                             daemon=True).start()

    def _atender(self, conn):
        try:
            conn.settimeout(None)
            try:
                conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            numero = self.obter_numero()
            if numero is None or not self.notox.status_conexao_amigo(numero):
                conn.close()
                return
            ok, info = self.tuneis.abrir(self.sid, "porta")
            if not ok:
                log.warning("Túnel da porta %d recusado: %s", self.porta, info)
                conn.close()
                return
            tid, fila = info
            self.tuneis.bombear(conn, tid, fila, numero)
        except Exception:
            log.exception("erro no túnel da porta local")
            try:
                conn.close()
            except Exception:
                pass

    def parar(self):
        self._parar.set()
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass
        log.info("Porta local 127.0.0.1:%d fechada", self.porta)


# ===========================================================================
# APLICAÇÃO FLASK
# ===========================================================================

app = Flask(__name__, static_folder=DIR_STATIC, static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = None

if _TEM_WEBSOCKET:
    sock = Sock(app)

config = ConfigCliente(ARQ_CONFIG)
notox = _NoTox(ARQ_SAVE_TOX)
gerenciador = GerenciadorRequisicoes(notox, lambda: config["numero_amigo_servidor"])
tuneis = GerenciadorTuneis(notox, lambda: config["numero_amigo_servidor"])

_estado = {
    "amigo_conectado": False,
    "servicos": [],
    "lista_ok": False,
}
_dica_servidor = {}
_ssh_pendentes = {}
_listeners = {}
_listeners_lock = threading.Lock()


def _sincronizar_listeners():
    """Abre/fecha as portas locais conforme os serviços com 'porta
    externa' publicados pelo servidor."""
    try:
        desejados = {}
        for s in list(_estado["servicos"]):
            if s.get("porta_externa") and s.get("porta_cliente"):
                try:
                    desejados[s["id"]] = int(s["porta_cliente"])
                except (TypeError, ValueError):
                    pass
        with _listeners_lock:
            for sid in list(_listeners):
                l = _listeners[sid]
                if (sid not in desejados or l.porta != desejados[sid]
                        or not l.ok):
                    l.parar()
                    del _listeners[sid]
            for sid, porta in desejados.items():
                if sid not in _listeners:
                    l = ListenerPorta(sid, porta, tuneis,
                                      lambda: config["numero_amigo_servidor"],
                                      notox)
                    _listeners[sid] = l
                    l.iniciar()
    except Exception:
        log.exception("sincronizar_listeners")


def _on_status_rede(status):
    pass


def _enviar_dica_rede(numero):
    try:
        dht, porta, ips = notox.dht_id_hex(), notox.porta_udp(), _ips_lan_locais()
        if dht and porta and ips:
            notox.enviar(numero, {"tipo": "dica_rede", "dht_id": dht,
                                  "porta": porta, "ips": ips})
        notox.enviar(numero, {"tipo": "dica_rede_pedir"})
    except Exception as e:
        log.debug("enviar dica_rede: %s", e)


def _receber_dica_rede(msg):
    try:
        ips = [i for i in (msg.get("ips") or [])[:6] if _ip_lan_valido(i)]
        dht = str(msg.get("dht_id", ""))
        porta = int(msg.get("porta", 0))
        if not ips or not RE_HEX64.match(dht) or not 1024 <= porta <= 65535:
            return
        _dica_servidor.clear()
        _dica_servidor.update({"ips": ips, "dht_id": dht, "porta": porta})
        n = notox.aplicar_dica_lan(ips, porta, dht)
        log.info("Dica de rede do servidor: %s:%d (bootstrap %d)",
                 ", ".join(ips), porta, n)
    except Exception:
        log.exception("receber dica_rede")


def _loop_rota():
    """Enquanto estiver só via relay TCP, re-tenta a rota direta."""
    while True:
        time.sleep(DICA_REDE_INTERVALO)
        try:
            numero = config["numero_amigo_servidor"]
            if numero is None or notox.status_amigo(numero) != 1:
                continue
            if _dica_servidor:
                notox.aplicar_dica_lan(_dica_servidor["ips"],
                                       _dica_servidor["porta"],
                                       _dica_servidor["dht_id"])
            _enviar_dica_rede(numero)
        except Exception:
            log.exception("loop_rota")


def _on_status_amigo(numero, status):
    conectado = status != 0
    if numero == config["numero_amigo_servidor"]:
        _estado["amigo_conectado"] = conectado
        if conectado:
            threading.Thread(target=_enviar_dica_rede, args=(numero,),
                             daemon=True, name="Dica").start()
        if not conectado:
            _estado["servicos"] = []
            _estado["lista_ok"] = False
            gerenciador.ao_amigo_desconectar(numero)
            tuneis.ao_amigo_desconectar()
            _sincronizar_listeners()
        if _TEM_TRAY and _tray_icon is not None:
            _atualizar_icone_tray()


def _on_mensagem(numero, msg):
    tipo = msg.get("tipo", "")
    if tipo == "dica_rede":
        _receber_dica_rede(msg)
    elif tipo == "lista_servicos":
        _estado["servicos"] = msg.get("dados", [])
        _estado["lista_ok"] = True
        _sincronizar_listeners()
    elif tipo.startswith("http_resposta"):
        gerenciador.tratar_mensagem(numero, msg)
    elif tipo.startswith("tcp_"):
        tuneis.tratar(msg)
    elif tipo in ("ssh_aberto", "ssh_dados", "ssh_erro", "ssh_fechado"):
        sid = msg.get("session_id")
        fila = _ssh_pendentes.get(sid)
        if fila:
            fila.put(msg)
    else:
        log.debug(f"Mensagem ignorada (tipo={tipo})")


notox.cb_status_rede = _on_status_rede
notox.cb_status_amigo = _on_status_amigo
notox.cb_msg = _on_mensagem


def _loop_servicos():
    while True:
        time.sleep(5)
        numero = config["numero_amigo_servidor"]
        if numero is not None and notox.status_conexao_amigo(numero):
            try:
                notox.enviar(numero, {"tipo": "listar_servicos"})
            except Exception:
                pass


def _loop_bootstrap_periodico():
    while True:
        time.sleep(1800)
        try:
            if notox.status_rede() == 0:
                _atualizar_nos_online()
                notox.bootstrap_otimizado(_carregar_nos())
        except Exception:
            log.exception("bootstrap periódico")


class _RespostaEncerrada(Response):
    """Resposta 'vazia' para depois que o socket foi tomado pelo túnel
    (mesmo truque do flask_sock): impede o werkzeug de escrever na
    conexão já encerrada."""

    def __call__(self, *args, **kwargs):
        raise ConnectionError()


def _tunel_websocket(service_id, path):
    """Repassa um upgrade WebSocket do navegador como túnel TCP cru."""
    raw = request.environ.get("werkzeug.socket")
    if raw is None:
        return Response("WebSocket não suportado por esta versão do servidor local "
                        "(atualize o werkzeug: pip install -U werkzeug).",
                        status=501, mimetype="text/plain")
    numero = config["numero_amigo_servidor"]
    if numero is None or not notox.status_conexao_amigo(numero):
        return Response("Servidor remoto não está conectado (Tox offline).",
                        status=503, mimetype="text/plain")
    headers = [[k, v] for k, v in request.headers.items()]
    log.info("proxy WebSocket %s", path.split("?", 1)[0])
    ok, info = tuneis.abrir(service_id, "ws",
                            {"path": path, "headers": headers})
    if not ok:
        return Response(f"Falha ao abrir WebSocket pelo Tox: {info}",
                        status=502, mimetype="text/plain")
    tid, fila = info
    try:
        raw.settimeout(None)
    except Exception:
        pass
    tuneis.bombear(raw, tid, fila, numero)
    return _RespostaEncerrada()


@app.before_request
def _rotear_proxy():
    host = request.host or ""
    m = RE_SUBDOMINIO.match(host)
    if not m:
        return None
    service_id = m.group(1)

    if request.path == "/__rrfs_polyfill.js":
        return Response(POLYFILL_JS, mimetype="application/javascript",
                        headers={"Cache-Control": "no-store"})

    path = request.path
    if request.query_string:
        path += "?" + request.query_string.decode("utf-8", "ignore")

    if request.headers.get("Upgrade", "").lower() == "websocket":
        return _tunel_websocket(service_id, path)

    return gerenciador.encaminhar(
        service_id=service_id,
        method=request.method,
        path=path,
        headers=dict(request.headers),
        stream_entrada=request.stream,
        tamanho_entrada=request.content_length,
    )


PAINEL_HTML = r"""<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RRFS Servidores</title>
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<link rel="stylesheet" href="/static/xterm.css">
<style>
  body{background:#121212;color:#eee;font-family:Segoe UI,Arial,sans-serif;margin:0;padding:20px}
  h1{color:#4fd1c5;display:flex;justify-content:space-between;align-items:center;font-size:22px;margin:0 0 12px;flex-wrap:wrap;gap:10px}
  .titulo{display:flex;align-items:center;gap:10px}
  .logo{height:38px;width:38px;border-radius:9px;box-shadow:0 0 0 1px #333}
  .barra{display:flex;gap:8px;flex-wrap:wrap}
  .grade{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:16px;margin-top:20px}
  .cartao{background:#1e1e1e;border:1px solid #333;border-radius:10px;padding:16px;display:flex;flex-direction:column}
  .cartao h3{margin:0 0 8px;color:#4fd1c5}
  .cartao p{color:#aaa;font-size:14px;min-height:40px;margin:0 0 10px}
  .btn,button{padding:8px 14px;background:#4fd1c5;border:none;border-radius:6px;color:#111;font-weight:bold;cursor:pointer;text-decoration:none;text-align:center;font-size:14px}
  .cartao .btn,.cartao button{margin-top:6px}
  .cartao .ultimo{margin-top:auto}
  .sec{background:#555;color:#eee}
  .status{font-size:13px;margin:0 0 10px}
  .ok{color:#6bffb0}.aviso{color:#f6c343}.erro{color:#ff6b6b}
  .porta{font-family:monospace;font-size:13px;margin:0 0 8px;background:#151515;border:1px solid #333;border-radius:6px;padding:8px;word-break:break-all}
  .dica{font-size:12px;color:#888;margin:0 0 8px}
  .diag{background:#1e1e1e;border:1px solid #333;border-radius:8px;padding:12px 14px;font-size:14px;color:#ccc;margin-top:14px}
  .id{font-family:monospace;font-size:12px;color:#888;word-break:break-all;margin-top:14px}
  .modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center}
  .oculto{display:none}
  .modal-conteudo{background:#1e1e1e;padding:20px;border-radius:10px;width:760px;max-width:96%}
  .modal-conteudo input{width:100%;box-sizing:border-box;margin-bottom:10px;padding:8px;background:#2a2a2a;border:1px solid #444;color:#eee;border-radius:6px}
  #terminal-ssh{height:430px;background:#000;border-radius:6px;padding:6px;overflow:hidden}
</style>
</head>
<body>
<h1>
  <span class="titulo"><img src="/static/logo.png" alt="RRFS Servidores" class="logo"> RRFS Servidores</span>
  <span class="barra">
    <button class="sec" onclick="atualizarNos(this)" title="Baixa a lista pública de nós Tox (precisa de internet)">⬇ Nós Tox</button>
    <button class="sec" onclick="sair()">Sair</button>
  </span>
</h1>

<p class="status" id="status">Carregando…</p>
<div class="diag" id="diag" style="display:none"></div>
<div class="grade" id="grade"></div>
<div class="id">Meu ID Tox (cliente): <span id="meuId">--</span></div>

<div id="modal-ssh" class="modal oculto">
  <div class="modal-conteudo">
    <div id="form-ssh-login">
      <h3>Login SSH</h3>
      <input id="ssh-usuario" placeholder="usuário" autocomplete="off">
      <input id="ssh-senha" type="password" placeholder="senha" autocomplete="off" onkeydown="if(event.key==='Enter')iniciarSSH()">
      <button onclick="iniciarSSH()">Conectar</button>
      <button class="sec" onclick="fecharModal()">Cancelar</button>
    </div>
    <div id="area-term" style="display:none">
      <div style="display:flex;justify-content:space-between;margin-bottom:6px"><b>Terminal SSH</b><button class="sec" onclick="fecharModal()">Fechar</button></div>
      <div id="terminal-ssh"></div>
    </div>
  </div>
</div>

<script src="/static/xterm.js"></script>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let ultimo='';

function diagnostico(e){
  if(!e.sessao)return 'Sem servidor configurado. Saia e informe o ID Tox do servidor.';
  if(e.status_rede===0)return `Sem conexão com a rede Tox. ${e.nos_bootstrap?`Tentando ${e.nos_bootstrap} nós de bootstrap…`:'Nenhum nó de bootstrap salvo: clique em "⬇ Nós Tox" (precisa de internet) ou use a mesma rede local do servidor.'}`;
  if(!e.conectado)return `Rede Tox OK, mas o servidor (${esc(e.servidor_id)}) não está conectado. Verifique: (1) o Tox está ativo no servidor; (2) o pedido de amizade foi APROVADO no painel do servidor (Acesso Remoto Tox → Amigos); (3) o ID informado está correto. Meu ID para aprovar: veja abaixo.`;
  if(!e.lista_ok)return 'Servidor conectado. Consultando a lista de serviços…';
  if(!e.servicos.length)return 'O servidor respondeu, mas não há serviços publicados. No painel do servidor: Acesso Remoto Tox → Serviços → clique em "Ativar" no serviço desejado.';
  return '';
}

function copiar(t){
  try{navigator.clipboard.writeText(t)}catch(e){const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove()}
}

function render(e){
  const rede=e.status_rede===0?'<span class="erro">● Offline da rede Tox</span>'
    :e.status_rede===1?'<span class="aviso">● Rede Tox via TCP (retransmissor)</span>'
    :'<span class="ok">● Rede Tox via UDP (direto)</span>';
  const rota=!e.conectado?'':e.rota===2?' &nbsp;|&nbsp; <span class="ok">Caminho: UDP direto'+(e.rota_lan?' (LAN disponível)':'')+'</span>'
    :' &nbsp;|&nbsp; <span class="aviso">Caminho: relay TCP'+(e.rota_lan?' (tentando rota direta na LAN…)':'')+'</span>';
  $('status').innerHTML=rede+' &nbsp;|&nbsp; '+(e.conectado?'<span class="ok">Servidor: online</span>':'<span class="erro">Servidor: offline</span>')+rota;
  const d=diagnostico(e);
  $('diag').style.display=d?'block':'none';$('diag').innerHTML=d;
  $('meuId').textContent=e.meu_id||'--';
  const base=location.port?':'+location.port:'';
  const html=(e.servicos||[]).map(s=>{
    let acoes='';
    if(s.tipo==='ssh')acoes+=`<button onclick="abrirSSH()">Abrir Terminal</button>`;
    else if(s.tipo==='http')acoes+=`<a class="btn" target="_blank" rel="noopener" href="http://s-${encodeURIComponent(s.id)}.localhost${base}/">Abrir</a>`;
    let porta='';
    if(s.porta_externa){
      const end='127.0.0.1:'+s.porta_cliente;
      if(s.porta_local_ok){
        porta=`<div class="porta ok">🔌 Porta local: <b>${esc(end)}</b></div>
          <div class="dica">${s.tipo==='tcp'?'Configure o aplicativo (ex.: Winbox → Connect To) com este endereço.':'Use este endereço em aplicativos nativos (cliente SSH, VNC, RDP...).'}</div>`;
        acoes+=`<button class="sec" onclick="copiar('${esc(end)}')">📋 Copiar ${esc(end)}</button>`;
      }else{
        porta=`<div class="porta erro">🔌 ${esc(s.porta_local_erro||'Abrindo porta local…')}</div>`;
      }
    }
    return `<div class="cartao"><h3>${esc(s.nome)}</h3><p>${esc(s.comentario||'')}</p>${porta}<div class="ultimo" style="display:flex;flex-direction:column">${acoes}</div></div>`}).join('');
  if(html!==ultimo){$('grade').innerHTML=html;ultimo=html}
}

async function atualizar(){
  try{const r=await fetch('/api/estado');if(r.status===200)render(await r.json())}
  catch(e){$('status').innerHTML='<span class="erro">Cliente local não responde</span>'}
}

async function atualizarNos(b){b.disabled=true;b.textContent='Buscando…';
  try{const d=await (await fetch('/api/bootstrap/atualizar',{method:'POST'})).json();
    alert(d.ok?`Lista atualizada (+${d.novos} nós).`:'Sem acesso à lista online (sem internet?).')}catch(e){alert('Erro')}
  b.disabled=false;b.textContent='⬇ Nós Tox';atualizar()}

async function sair(){await fetch('/api/logout',{method:'POST'});location.href='/login'}

let sock=null,term=null;
function abrirSSH(){$('modal-ssh').classList.remove('oculto');$('ssh-usuario').focus()}
function fecharModal(){
  $('modal-ssh').classList.add('oculto');
  if(sock){try{sock.send(JSON.stringify({tipo:'fechar'}))}catch(e){}sock.close();sock=null}
  if(term){term.dispose();term=null}
  $('form-ssh-login').style.display='block';$('area-term').style.display='none';
  $('terminal-ssh').innerHTML='';$('ssh-senha').value='';
}
function iniciarSSH(){
  const usuario=$('ssh-usuario').value,senha=$('ssh-senha').value;
  if(!usuario)return;
  if(typeof Terminal==='undefined'){alert('xterm.js não carregou (static/xterm.js ausente).');return}
  $('form-ssh-login').style.display='none';$('area-term').style.display='block';
  term=new Terminal({cols:80,rows:24,fontSize:14,cursorBlink:true,theme:{background:'#000',foreground:'#eee'}});
  term.open($('terminal-ssh'));term.focus();
  term.write('Conectando via Tox…\r\n');
  sock=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host+'/ws/ssh');
  sock.onopen=()=>sock.send(JSON.stringify({usuario,senha}));
  sock.onmessage=ev=>{
    const m=JSON.parse(ev.data);
    if(m.tipo==='dados'){const b=atob(m.dados),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);term.write(u)}
    else if(m.tipo==='conectado')term.write('\x1b[32mConectado.\x1b[0m\r\n');
    else if(m.tipo==='erro')term.write('\r\n\x1b[31m[ERRO] '+(m.mensagem||'')+'\x1b[0m\r\n');
    else if(m.tipo==='fechado')term.write('\r\n[Sessão encerrada]\r\n');
  };
  sock.onclose=()=>{if(term)term.write('\r\n[Conexão com o cliente encerrada]\r\n')};
  term.onData(d=>{if(sock&&sock.readyState===1)sock.send(JSON.stringify({tipo:'tecla',dados:d}))});
}

atualizar();setInterval(atualizar,3000);
</script>
</body>
</html>"""

LOGIN_HTML = r"""<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RRFS Servidores - Login</title>
<link rel="icon" type="image/x-icon" href="/static/favicon.ico">
<style>
  body{background:#121212;color:#eee;font-family:Segoe UI,Arial,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}
  .caixa{background:#1e1e1e;padding:30px;border-radius:10px;width:460px;box-shadow:0 0 20px rgba(0,0,0,.5);}
  .cabecalho{display:flex;align-items:center;gap:12px;margin-bottom:6px;}
  .cabecalho img{height:52px;width:52px;border-radius:12px;box-shadow:0 0 0 1px #333;}
  .cabecalho .nomes{display:flex;flex-direction:column;}
  .cabecalho h1{margin:0;color:#4fd1c5;font-size:20px;}
  .cabecalho span{font-size:12px;color:#888;}
  h2{margin:18px 0 4px;color:#4fd1c5;font-size:16px;font-weight:600;}
  textarea{width:100%;background:#2a2a2a;color:#eee;border:1px solid #444;border-radius:6px;padding:10px;min-height:70px;font-family:monospace;box-sizing:border-box;}
  button{margin-top:12px;width:100%;padding:10px;background:#4fd1c5;border:none;border-radius:6px;color:#111;font-weight:bold;cursor:pointer;font-size:14px;}
  button:hover{background:#3fc2b5;}
  .erro{color:#ff6b6b;margin-top:10px;font-size:13px;}
  p{font-size:13px;color:#999;}
</style>
</head>
<body>
<div class="caixa">
  <div class="cabecalho">
    <img src="/static/logo.png" alt="RRFS Servidores">
    <div class="nomes">
      <h1>RRFS Servidores</h1>
      <span>Acesso remoto via protocolo Tox</span>
    </div>
  </div>
  <h2>🔑 Conectar ao Servidor (Tox)</h2>
  <p>Cole o ID Tox (76 caracteres) exibido no painel do servidor:</p>
  <textarea id="endereco" placeholder="Endereço Tox (hex)..." autocomplete="off" onkeydown="if(event.key==='Enter'&&event.ctrlKey)entrar()"></textarea>
  <button onclick="entrar()">Conectar</button>
  <div class="erro" id="erro"></div>
</div>
<script>
async function entrar(){
  const endereco = document.getElementById('endereco').value.trim();
  const erroDiv = document.getElementById('erro'); erroDiv.textContent = '';
  try{
    const resp = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({endereco})});
    const dados = await resp.json();
    if(dados.ok){ window.location.href = '/'; } else { erroDiv.textContent = dados.erro || 'Falha'; }
  }catch(e){ erroDiv.textContent = 'Erro: ' + e; }
}
</script>
</body>
</html>"""


@app.route("/")
def painel():
    return Response(PAINEL_HTML, mimetype="text/html")


@app.route("/login")
def login_pagina():
    return Response(LOGIN_HTML, mimetype="text/html")


@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(force=True, silent=True) or {}
    endereco = (d.get("endereco") or "").strip().upper()
    if not RE_ADDR.match(endereco):
        return jsonify({"ok": False, "erro": "Endereço Tox inválido (precisa ter 76 caracteres hex)."})
    try:
        numero = notox.adicionar_amigo_por_endereco(endereco)
    except Exception as e:
        log.exception("api_login")
        return jsonify({"ok": False, "erro": str(e)})
    config["tox_id_servidor"] = endereco
    config["numero_amigo_servidor"] = numero
    _estado["servicos"] = []
    _estado["lista_ok"] = False
    _sincronizar_listeners()
    return jsonify({"ok": True})


@app.route("/api/logout", methods=["POST"])
def api_logout():
    config["tox_id_servidor"] = ""
    config["numero_amigo_servidor"] = None
    _estado["servicos"] = []
    _estado["lista_ok"] = False
    _estado["amigo_conectado"] = False
    _sincronizar_listeners()
    return jsonify({"ok": True})


@app.route("/api/estado")
def api_estado():
    numero = config["numero_amigo_servidor"]
    conectado = bool(numero is not None and notox.status_conexao_amigo(numero))
    tox_id_servidor = config["tox_id_servidor"] or ""

    servicos = []
    if conectado:
        for s in _estado["servicos"]:
            d = dict(s)
            if d.get("porta_externa"):
                with _listeners_lock:
                    l = _listeners.get(d.get("id"))
                d["porta_local_ok"] = bool(l and l.ok)
                d["porta_local_erro"] = (l.erro if l and l.erro
                                         else "Abrindo porta local…")
            servicos.append(d)

    return jsonify({
        "sessao": bool(tox_id_servidor),
        "status_rede": notox.status_rede(),
        "rota": notox.status_amigo(numero) if numero is not None else 0,
        "rota_lan": bool(_dica_servidor),
        "conectado": conectado,
        "servidor_id": (tox_id_servidor[:16] + "...") if tox_id_servidor else "",
        "nos_bootstrap": len(_carregar_nos()),
        "lista_ok": _estado["lista_ok"] if conectado else False,
        "servicos": servicos,
        "meu_id": notox.endereco_hex(),
    })


@app.route("/api/bootstrap/atualizar", methods=["POST"])
def api_bootstrap_atualizar():
    ok, novos = _atualizar_nos_online()
    if ok:
        try:
            notox.bootstrap(_carregar_nos())
        except Exception:
            pass
    return jsonify({"ok": ok, "novos": novos})


if _TEM_WEBSOCKET:

    @sock.route("/ws/ssh")
    def ws_ssh(ws):
        numero = config["numero_amigo_servidor"]
        if numero is None or not notox.status_conexao_amigo(numero):
            try:
                ws.send(json.dumps({"tipo": "erro", "mensagem": "Servidor não conectado."}))
            except Exception:
                pass
            return

        try:
            primeira = ws.receive(timeout=15)
            dados_login = json.loads(primeira) if primeira else {}
        except Exception:
            return
        usuario = dados_login.get("usuario", "")
        senha = dados_login.get("senha", "")

        session_id = uuid.uuid4().hex
        fila = queue.Queue()
        _ssh_pendentes[session_id] = fila

        try:
            notox.enviar(numero, {"tipo": "ssh_abrir", "session_id": session_id,
                                   "usuario": usuario, "senha": senha})
        except Exception as e:
            try:
                ws.send(json.dumps({"tipo": "erro", "mensagem": str(e)}))
            except Exception:
                pass
            _ssh_pendentes.pop(session_id, None)
            return

        parar = threading.Event()

        def _ler_do_servidor():
            while not parar.is_set():
                try:
                    msg = fila.get(timeout=0.5)
                except queue.Empty:
                    continue
                tipo = msg.get("tipo")
                try:
                    if tipo == "ssh_aberto":
                        ws.send(json.dumps({"tipo": "conectado"}))
                    elif tipo == "ssh_dados":
                        ws.send(json.dumps({"tipo": "dados", "dados": msg.get("dados", "")}))
                    elif tipo == "ssh_erro":
                        ws.send(json.dumps({"tipo": "erro", "mensagem": msg.get("mensagem", "")}))
                        break
                    elif tipo == "ssh_fechado":
                        ws.send(json.dumps({"tipo": "fechado"}))
                        break
                except Exception:
                    break

        t = threading.Thread(target=_ler_do_servidor, daemon=True)
        t.start()

        try:
            while True:
                msg = ws.receive()
                if msg is None:
                    break
                try:
                    d = json.loads(msg)
                except Exception:
                    continue
                if d.get("tipo") == "tecla":
                    bruto = d.get("dados", "").encode("utf-8")
                    try:
                        notox.enviar(numero, {"tipo": "ssh_dados", "session_id": session_id,
                                               "dados": base64.b64encode(bruto).decode("ascii")})
                    except Exception:
                        break
                elif d.get("tipo") == "fechar":
                    break
        finally:
            parar.set()
            _ssh_pendentes.pop(session_id, None)
            try:
                notox.enviar(numero, {"tipo": "ssh_fechar", "session_id": session_id})
            except Exception:
                pass


# ===========================================================================
# BANDEJA DO SISTEMA
# ===========================================================================

_tray_icon = None


def _carregar_imagem_icone():
    """Carrega o ícone da bandeja já no tamanho final (128x128).
    Entregar um PNG 512x512 ao pystray faz o KDE reduzir sem filtro e o
    ícone fica borrado; por isso preferimos static/tray.png (pré-gerado) e,
    na falta dele, reduzimos o logo com LANCZOS."""
    for nome in ("tray.png", "logo.png"):
        caminho = os.path.join(DIR_STATIC, nome)
        if os.path.exists(caminho):
            try:
                img = Image.open(caminho).convert("RGBA")
                if img.size != (128, 128):
                    img = img.resize((128, 128), Image.LANCZOS)
                return img
            except Exception:
                pass
    img = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.ellipse((8, 8, 120, 120), fill=(79, 209, 197, 255))
    d.ellipse((40, 40, 88, 88), fill=(17, 17, 17, 255))
    return img


def _atualizar_icone_tray():
    if not _TEM_TRAY or _tray_icon is None:
        return
    try:
        _tray_icon.title = (f"RRFS Cliente Tox - "
                             f"{'servidor online' if _estado['amigo_conectado'] else 'servidor offline'}")
    except Exception:
        pass


def _abrir_painel(icon=None, item=None):
    url = f"http://127.0.0.1:{PORTA_LOCAL}/"
    # Dentro do distrobox não há navegador: pede ao sistema do usuário
    # (host) que abra a URL no navegador padrão dele.
    if os.environ.get("CONTAINER_ID") or os.path.exists("/run/.containerenv"):
        for cmd in (["distrobox-host-exec", "xdg-open", url],
                    ["host-spawn", "xdg-open", url]):
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
                return
            except Exception:
                continue
    import webbrowser
    webbrowser.open(url)


def _sair(icon=None, item=None):
    log.info("Encerrando cliente (bandeja)")
    try:
        notox.parar()
    finally:
        if _tray_icon is not None:
            _tray_icon.stop()
        os._exit(0)


def iniciar_tray():
    global _tray_icon
    imagem = _carregar_imagem_icone()
    menu = pystray.Menu(
        pystray.MenuItem("Abrir painel", _abrir_painel, default=True),
        pystray.MenuItem("Sair", _sair),
    )
    _tray_icon = pystray.Icon("rrfs_cliente_tox", imagem, "RRFS Cliente Tox", menu)
    _tray_icon.run()


# ===========================================================================
# PONTO DE ENTRADA
# ===========================================================================

def main():
    log.info("=== RRFS Cliente Tox v%s iniciando ===", VERSAO)
    log.info("Meu Tox ID: %s", notox.endereco_hex())

    if not _TEM_WEBSOCKET:
        log.warning("flask_sock não instalado - SSH via navegador ficará indisponível "
                    "(pip install flask-sock)")

    # HTTP/1.1: keep-alive e chunked (truncamento passa a ser detectável)
    try:
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.protocol_version = "HTTP/1.1"
    except Exception:
        log.warning("Não foi possível ativar HTTP/1.1 no servidor local")

    nos = _carregar_nos()
    if nos:
        notox.bootstrap(nos)

    def _bootstrap_online_inicial():
        _atualizar_nos_online()
        try:
            notox.bootstrap_otimizado(_carregar_nos())
        except Exception:
            log.exception("bootstrap otimizado inicial")
    threading.Thread(target=_bootstrap_online_inicial,
                     name="BootstrapInicialOnline", daemon=True).start()

    notox.iniciar_loop()

    threading.Thread(target=_loop_servicos, name="Servicos", daemon=True).start()
    threading.Thread(target=_loop_rota, name="Rota", daemon=True).start()
    threading.Thread(target=_loop_bootstrap_periodico, name="BootstrapLoop", daemon=True).start()

    numero = config["numero_amigo_servidor"]
    if numero is not None:
        log.info("Servidor configurado (amigo #%s) - aguardando conexão...", numero)

    def _rodar_flask():
        app.run(host="127.0.0.1", port=PORTA_LOCAL, threaded=True, use_reloader=False)

    t_flask = threading.Thread(target=_rodar_flask, name="Flask", daemon=True)
    t_flask.start()

    log.info("Painel disponível em http://127.0.0.1:%d/", PORTA_LOCAL)

    if _TEM_TRAY:
        try:
            iniciar_tray()
        except Exception:
            log.exception("Falha ao iniciar bandeja do sistema, rodando apenas como serviço")
            while True:
                time.sleep(1)
    else:
        log.info("pystray/PIL não disponíveis - rodando sem ícone de bandeja")
        while True:
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _sair()
    except Exception:
        log.exception("Erro fatal no cliente")
        sys.exit(1)
