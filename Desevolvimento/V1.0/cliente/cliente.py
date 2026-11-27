#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 CLIENTE DE ACESSO REMOTO VIA PROTOCOLO TOX (PAINEL PORTA 2100) v2.1
=====================================================================
v2.1:
  - Lista de serviços atualizada em segundo plano e exibida pela página
    (antes era pedida UMA vez no carregamento; se o servidor ainda não
    estivesse conectado, os botões nunca apareciam)
  - Cada site abre em  http://s-<id>.localhost:2100/  (origem própria:
    links absolutos, cookies e CSS/JS funcionam; antes /proxy/<id>/
    quebrava a maioria dos sites)
  - Compatível com o formato novo de cabeçalhos do servidor (lista de
    pares) - o formato antigo (dict) também é aceito
  - Corrige Content-Encoding/Location/Set-Cookie na resposta
  - Bootstrap: chaves inválidas (63 hex) descartadas, lista online,
    relays TCP
  - xterm.js local (static/), sem CDN; bytes UTF-8 corretos
  - Proteção contra páginas externas: valida Host e Origin (HTTP e WS)
  - Envio Tox com retry de fila cheia e checagem de conexão
"""

import os, sys, re, json, time, uuid, math, base64, queue, struct, secrets
import threading, ipaddress
import ctypes, ctypes.util
import urllib.request
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from flask import (Flask, request, jsonify, render_template, redirect,
                   url_for, Response)

try:
    from flask_sock import Sock
except ImportError:
    print("Instale: pip install flask-sock"); sys.exit(1)

# =====================================================================
PORTA = 2100
BASE_DIR   = Path(__file__).resolve().parent
DADOS_DIR  = BASE_DIR / "dados"
SESSAO_DIR = DADOS_DIR / "sessao"
CONFIG_DIR = DADOS_DIR / "config"
LOG_DIR    = DADOS_DIR / "logs"
for d in (DADOS_DIR, SESSAO_DIR, CONFIG_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)
try:
    os.chmod(SESSAO_DIR, 0o700)
except Exception:
    pass

ARQ_SAVEDATA  = SESSAO_DIR / "identidade.tox"
ARQ_SERVIDOR  = SESSAO_DIR / "servidor.json"
ARQ_BOOTSTRAP = CONFIG_DIR / "nos_bootstrap.json"
ARQ_LOG       = LOG_DIR / "cliente.log"

RE_HEX64 = re.compile(r'^[0-9A-Fa-f]{64}$')
RE_ADDR  = re.compile(r'^[0-9A-Fa-f]{76}$')
_trava_log = threading.Lock()


def log(msg):
    linha = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(linha, flush=True)
    try:
        with _trava_log, open(ARQ_LOG, "a", encoding="utf-8") as f:
            f.write(linha + "\n")
    except Exception:
        pass


def carregar_json(caminho, padrao):
    if caminho.exists():
        try:
            with open(caminho, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return padrao
    return padrao


def salvar_json(caminho, dados):
    tmp = caminho.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(dados, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(caminho)


# =====================================================================
# BOOTSTRAP
# =====================================================================
def obter_nos_bootstrap():
    """Só retorna nós com chave pública válida (64 hex)."""
    nos = carregar_json(ARQ_BOOTSTRAP, [])
    validos = [n for n in nos
               if isinstance(n, dict) and RE_HEX64.match(n.get("chave_publica", ""))
               and n.get("ip")]
    if len(validos) != len(nos):
        salvar_json(ARQ_BOOTSTRAP, validos)   # remove os inválidos do arquivo
    return validos


def atualizar_nos_bootstrap_online():
    try:
        req = urllib.request.Request("https://nodes.tox.chat/json",
                                     headers={"User-Agent": "RRFS-Tox-Cliente"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            dados = json.loads(resp.read().decode("utf-8"))
        atuais = obter_nos_bootstrap()
        existentes = {(n["ip"], int(n["porta"])) for n in atuais}
        novos = 0
        for it in dados.get("nodes", []):
            ip = it.get("ipv4")
            chave = (it.get("public_key") or "").upper()
            if (not it.get("status_udp") or not ip or ip == "-"
                    or not RE_HEX64.match(chave)):
                continue
            porta = int(it.get("port", 33445))
            if (ip, porta) in existentes:
                continue
            atuais.append({"ip": ip, "porta": porta, "chave_publica": chave,
                           "tcp_ports": it.get("tcp_ports") or [],
                           "origem": "nodes.tox.chat"})
            existentes.add((ip, porta))
            novos += 1
        salvar_json(ARQ_BOOTSTRAP, atuais)
        return True, novos
    except Exception as e:
        log(f"Falha ao atualizar bootstrap (sem internet?): {e}")
        return False, 0


def carregar_sessao():
    return carregar_json(ARQ_SERVIDOR, None)


def salvar_sessao(dados):
    salvar_json(ARQ_SERVIDOR, dados)


def excluir_sessao():
    if ARQ_SERVIDOR.exists():
        ARQ_SERVIDOR.unlink()


# =====================================================================
# LIBTOXCORE
# =====================================================================
TOX_ADDRESS_SIZE = 38
TOX_PUBLIC_KEY_SIZE = 32
PACOTE_ID_DADOS = 160
MAX_FRAGMENTO = 1200
MAX_FRAGMENTOS_MSG = 4000
MAX_CORPO = 3 * 1024 * 1024
ERRO_SENDQ = 7
_LIB = None


def carregar_libtoxcore():
    global _LIB
    if _LIB is not None:
        return _LIB
    nomes = ["libtoxcore.so", "libtoxcore.so.2", "libtoxcore.so.1", "libtoxcore.so.0"]
    caminho = ctypes.util.find_library("toxcore")
    if caminho:
        nomes.insert(0, caminho)
    erro_final = None
    for nome in nomes:
        try:
            lib = ctypes.CDLL(nome)
            _assinaturas(lib)
            _LIB = lib
            return lib
        except (OSError, AttributeError) as e:
            erro_final = e
    raise RuntimeError(f"Nao foi possivel carregar libtoxcore. Erro: {erro_final}")


def _assinaturas(lib):
    vp, ci = ctypes.c_void_p, ctypes.c_int
    u8p = ctypes.POINTER(ctypes.c_uint8)
    u32, u16 = ctypes.c_uint32, ctypes.c_uint16
    st, cb, cp = ctypes.c_size_t, ctypes.c_bool, ctypes.c_char_p
    eri = ctypes.POINTER(ci)

    def fn(nome, res, args):
        f = getattr(lib, nome)
        f.restype, f.argtypes = res, args

    fn('tox_options_new', vp, [eri]); fn('tox_options_free', None, [vp])
    fn('tox_options_set_ipv6_enabled', None, [vp, cb])
    fn('tox_options_set_udp_enabled', None, [vp, cb])
    fn('tox_options_set_local_discovery_enabled', None, [vp, cb])
    fn('tox_options_set_savedata_type', None, [vp, ci])
    fn('tox_options_set_savedata_data', None, [vp, u8p, st])
    fn('tox_new', vp, [vp, eri]); fn('tox_kill', None, [vp])
    fn('tox_bootstrap', cb, [vp, cp, u16, u8p, eri])
    fn('tox_add_tcp_relay', cb, [vp, cp, u16, u8p, eri])
    fn('tox_iteration_interval', u32, [vp]); fn('tox_iterate', None, [vp, vp])
    fn('tox_self_get_address', None, [vp, u8p])
    fn('tox_self_get_connection_status', ci, [vp])
    fn('tox_get_savedata_size', st, [vp]); fn('tox_get_savedata', None, [vp, u8p])
    fn('tox_friend_add', u32, [vp, u8p, u8p, st, eri])
    fn('tox_friend_delete', cb, [vp, u32, eri])
    fn('tox_friend_get_public_key', cb, [vp, u32, u8p, eri])
    fn('tox_friend_by_public_key', u32, [vp, u8p, eri])
    fn('tox_friend_send_lossless_packet', cb, [vp, u32, u8p, st, eri])
    fn('tox_self_get_friend_list_size', st, [vp])
    fn('tox_self_get_friend_list', None, [vp, ctypes.POINTER(u32)])
    fn('tox_callback_self_connection_status', None, [vp, vp])
    fn('tox_callback_friend_request', None, [vp, vp])
    fn('tox_callback_friend_connection_status', None, [vp, vp])
    fn('tox_callback_friend_lossless_packet', None, [vp, vp])


class NoTox:
    def __init__(self, caminho: Path, cb_mensagem, cb_amigo, log_fn=log):
        self.lib = carregar_libtoxcore()
        self.caminho = caminho
        self.cb_msg = cb_mensagem
        self.cb_amigo = cb_amigo
        self.log = log_fn
        self.tox = None
        self._rodando = False
        self._trava = threading.RLock()
        self._amigos = {}
        self._frag = {}
        self._refs = []
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
            if self.caminho.exists() and self.caminho.stat().st_size > 0:
                dados = self.caminho.read_bytes()
                self.lib.tox_options_set_savedata_type(op, 1)
                buf_save = (ctypes.c_uint8 * len(dados)).from_buffer_copy(dados)
                self.lib.tox_options_set_savedata_data(op, buf_save, len(dados))
            else:
                self.lib.tox_options_set_savedata_type(op, 0)
            e2 = ctypes.c_int(0)
            self.tox = self.lib.tox_new(op, ctypes.byref(e2))
            self.lib.tox_options_free(op)
            if not self.tox:
                raise RuntimeError(f"Falha ao criar Tox (codigo {e2.value})")
            self._callbacks()
            self._carregar_amigos()
            self._salvar_sem_trava()
        self.log(f"[Tox] Identidade cliente pronta. ID: {self.endereco_hex()}")

    def _callbacks(self):
        vp, u8p = ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8)
        CB_SELF = ctypes.CFUNCTYPE(None, vp, ctypes.c_int, vp)
        CB_REQ = ctypes.CFUNCTYPE(None, vp, u8p, u8p, ctypes.c_size_t, vp)
        CB_CONN = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, ctypes.c_int, vp)
        CB_PKT = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, u8p, ctypes.c_size_t, vp)

        def ao_rede(tox, status, ud):
            self.log("[Tox] Rede: " + {0: "Offline", 1: "Conectado(TCP)",
                                       2: "Conectado(UDP)"}.get(status, str(status)))

        def ao_pedido(tox, chave_ptr, msg_ptr, tam, ud):
            self.log("[Tox] Pedido de amizade ignorado (modo cliente)")

        def ao_amigo(tox, numero, status, ud):
            self._amigos.setdefault(numero, {})["status"] = status
            self.log(f"[Tox] Servidor (amigo {numero}): "
                     + {0: "desconectado", 1: "conectado(TCP)",
                        2: "conectado(UDP)"}.get(status, str(status)))
            try:
                self.cb_amigo(numero, status)
            except Exception as e:
                log(f"cb_amigo: {e}")

        def ao_pacote(tox, numero, dados_ptr, tam, ud):
            try:
                bruto = bytes(ctypes.cast(
                    dados_ptr, ctypes.POINTER(ctypes.c_uint8 * tam)).contents)
            except Exception:
                return
            self._fragmento(numero, bruto)

        self._c = [CB_SELF(ao_rede), CB_REQ(ao_pedido),
                   CB_CONN(ao_amigo), CB_PKT(ao_pacote)]
        L = self.lib
        L.tox_callback_self_connection_status(self.tox, self._c[0])
        L.tox_callback_friend_request(self.tox, self._c[1])
        L.tox_callback_friend_connection_status(self.tox, self._c[2])
        L.tox_callback_friend_lossless_packet(self.tox, self._c[3])

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
            self._amigos[numero] = {"chave_publica": bytes(kb).hex() if ok else "",
                                    "status": 0}

    # ── fragmentos ────────────────────────────────────────

    def _fragmento(self, numero, bruto):
        if len(bruto) < 9 or bruto[0] != PACOTE_ID_DADOS:
            return
        fid = bruto[1:5]
        idx = struct.unpack(">H", bruto[5:7])[0]
        total = struct.unpack(">H", bruto[7:9])[0]
        if total < 1 or total > MAX_FRAGMENTOS_MSG or idx >= total:
            return
        k = (numero, fid)
        reg = self._frag.setdefault(k, {"t": time.time(), "total": total, "p": {}})
        if reg["total"] != total:
            self._frag.pop(k, None)
            return
        reg["p"][idx] = bruto[9:]
        if len(reg["p"]) < total:
            return
        completo = b"".join(reg["p"][i] for i in range(total))
        self._frag.pop(k, None)
        try:
            msg = json.loads(completo.decode("utf-8"))
        except Exception:
            return
        threading.Thread(target=self.cb_msg, args=(numero, msg), daemon=True).start()

    def _limpar_fragmentos(self):
        agora = time.time()
        for k in [k for k, v in self._frag.items() if agora - v["t"] > 90]:
            self._frag.pop(k, None)

    def enviar_mensagem(self, numero, mensagem: dict):
        if not self.amigo_conectado(numero):
            raise RuntimeError("Servidor desconectado")
        bruto = json.dumps(mensagem).encode("utf-8")
        fid = secrets.token_bytes(4)
        total = max(1, math.ceil(len(bruto) / MAX_FRAGMENTO))
        if total > MAX_FRAGMENTOS_MSG:
            raise RuntimeError("Mensagem grande demais")
        for idx in range(total):
            pedaco = bruto[idx * MAX_FRAGMENTO:(idx + 1) * MAX_FRAGMENTO]
            pkt = (bytes([PACOTE_ID_DADOS]) + fid + struct.pack(">H", idx)
                   + struct.pack(">H", total) + pedaco)
            buf = (ctypes.c_uint8 * len(pkt)).from_buffer_copy(pkt)
            for _ in range(400):
                erro = ctypes.c_int(0)
                with self._trava:
                    if not self.tox:
                        raise RuntimeError("Tox parado")
                    ok = self.lib.tox_friend_send_lossless_packet(
                        self.tox, numero, buf, len(pkt), ctypes.byref(erro))
                if ok:
                    break
                if erro.value == ERRO_SENDQ:
                    time.sleep(0.05)
                    continue
                raise RuntimeError(f"Falha ao enviar pacote Tox (codigo {erro.value})")
            else:
                raise RuntimeError("Fila de envio Tox cheia (timeout)")

    # ── loops ─────────────────────────────────────────────

    def iniciar_loop(self):
        self._rodando = True
        threading.Thread(target=self._loop, daemon=True).start()
        threading.Thread(target=self._loop_salvar, daemon=True).start()

    def _loop(self):
        ult = time.time()
        while self._rodando:
            with self._trava:
                if not self._rodando or not self.tox:
                    break
                self.lib.tox_iterate(self.tox, None)
                intervalo = self.lib.tox_iteration_interval(self.tox)
            if time.time() - ult > 15:
                self._limpar_fragmentos()
                ult = time.time()
            time.sleep(max(intervalo, 10) / 1000.0)

    def _loop_salvar(self):
        while self._rodando:
            for _ in range(20):
                if not self._rodando:
                    return
                time.sleep(1)
            try:
                self.salvar()
            except Exception as e:
                log(f"[Tox] Erro salvando estado: {e}")

    def bootstrap(self, nos):
        for no in nos:
            try:
                chave = bytes.fromhex(no["chave_publica"])
                if len(chave) != TOX_PUBLIC_KEY_SIZE:
                    continue
                buf = (ctypes.c_uint8 * 32).from_buffer_copy(chave)
                host = no["ip"].encode()
                with self._trava:
                    if not self.tox:
                        return
                    e = ctypes.c_int(0)
                    self.lib.tox_bootstrap(self.tox, host, int(no["porta"]),
                                           buf, ctypes.byref(e))
                    tcp = int((no.get("tcp_ports") or [no["porta"]])[0])
                    self.lib.tox_add_tcp_relay(self.tox, host, tcp, buf, ctypes.byref(ctypes.c_int(0)))
            except Exception as e:
                log(f"[Tox] Erro bootstrap {no.get('ip')}: {e}")

    # ── estado / amigos ───────────────────────────────────

    def salvar(self):
        with self._trava:
            self._salvar_sem_trava()

    def _salvar_sem_trava(self):
        if not self.tox:
            return
        tam = self.lib.tox_get_savedata_size(self.tox)
        buf = (ctypes.c_uint8 * tam)()
        self.lib.tox_get_savedata(self.tox, buf)
        tmp = self.caminho.with_suffix(".tmp")
        tmp.write_bytes(bytes(buf))
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        tmp.replace(self.caminho)

    def endereco_hex(self):
        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE)()
        with self._trava:
            if not self.tox:
                return ""
            self.lib.tox_self_get_address(self.tox, buf)
        return bytes(buf).hex().upper()

    def status_rede(self):
        with self._trava:
            return self.lib.tox_self_get_connection_status(self.tox) if self.tox else 0

    def adicionar_amigo_por_endereco(self, endereco_hex, mensagem=b"RRFS cliente solicitando acesso"):
        eb = bytes.fromhex(endereco_hex.strip())
        if len(eb) != TOX_ADDRESS_SIZE:
            raise ValueError("Endereco Tox invalido (tamanho incorreto)")
        pub = eb[:TOX_PUBLIC_KEY_SIZE]
        with self._trava:
            erro = ctypes.c_int(0)
            bp = (ctypes.c_uint8 * 32).from_buffer_copy(pub)
            num = self.lib.tox_friend_by_public_key(self.tox, bp, ctypes.byref(erro))
            if erro.value == 0:
                self._amigos.setdefault(num, {"chave_publica": pub.hex(), "status": 0})
                return num
            ba = (ctypes.c_uint8 * TOX_ADDRESS_SIZE).from_buffer_copy(eb)
            bm = (ctypes.c_uint8 * len(mensagem)).from_buffer_copy(mensagem)
            erro = ctypes.c_int(0)
            num = self.lib.tox_friend_add(self.tox, ba, bm, len(mensagem), ctypes.byref(erro))
            if erro.value != 0:
                raise RuntimeError(f"Falha ao adicionar amigo (codigo {erro.value})")
        self._amigos[num] = {"chave_publica": pub.hex(), "status": 0}
        self.salvar()
        return num

    def remover_amigo(self, numero):
        with self._trava:
            if self.tox:
                self.lib.tox_friend_delete(self.tox, numero, ctypes.byref(ctypes.c_int(0)))
        self._amigos.pop(numero, None)
        self.salvar()

    def amigo_conectado(self, numero):
        info = self._amigos.get(numero)
        return bool(info and info.get("status", 0) != 0)


# =====================================================================
# REQUISIÇÕES (Request/Response sobre pacotes Tox)
# =====================================================================
class GerenciadorRequisicoes:
    def __init__(self):
        self.no = None
        self.numero = None
        self.pendentes = {}
        self.ssh_cb = {}
        self.lista = []
        self.lista_ok = False
        self.lista_ts = 0.0
        self.sem = threading.Semaphore(6)

    def despachar(self, numero, msg):
        if numero != self.numero or not isinstance(msg, dict):
            return
        tipo = msg.get("tipo")
        if tipo == "http_response":
            p = self.pendentes.get(msg.get("id"))
            if p:
                p["resposta"] = msg
                p["evento"].set()
        elif tipo in ("ssh_dados", "ssh_aberto", "ssh_erro", "ssh_fechado"):
            cb = self.ssh_cb.get(msg.get("session_id"))
            if cb:
                cb(msg)
        elif tipo == "lista_servicos":
            self.lista = msg.get("dados", []) or []
            self.lista_ok = True
            self.lista_ts = time.time()

    def conectado(self):
        return self.numero is not None and self.no is not None \
            and self.no.amigo_conectado(self.numero)

    def solicitar_lista(self):
        try:
            self.no.enviar_mensagem(self.numero, {"tipo": "listar_servicos"})
        except Exception as e:
            log(f"solicitar_lista: {e}")

    def http_request(self, service_id, method, path, headers, body, timeout=45):
        def erro(status, txt):
            return {"status": status, "headers": [],
                    "body": base64.b64encode(txt.encode()).decode()}
        if body and len(body) > MAX_CORPO:
            return erro(413, "Requisicao grande demais")
        rid = str(uuid.uuid4())
        p = {"evento": threading.Event(), "resposta": None}
        self.pendentes[rid] = p
        try:
            with self.sem:
                try:
                    self.no.enviar_mensagem(self.numero, {
                        "tipo": "http_request", "id": rid, "service_id": service_id,
                        "method": method, "path": path, "headers": headers,
                        "body": base64.b64encode(body).decode() if body else ""})
                except Exception as e:
                    return erro(502, f"Falha ao enviar pelo Tox: {e}")
                if p["evento"].wait(timeout):
                    return p["resposta"]
                return erro(504, "Timeout aguardando o servidor")
        finally:
            self.pendentes.pop(rid, None)

    def ssh_abrir(self, sid, usuario, senha, callback):
        self.ssh_cb[sid] = callback
        self.no.enviar_mensagem(self.numero, {"tipo": "ssh_abrir", "session_id": sid,
                                              "usuario": usuario, "senha": senha})

    def ssh_dados(self, sid, dados: bytes):
        try:
            self.no.enviar_mensagem(self.numero, {"tipo": "ssh_dados", "session_id": sid,
                                                  "dados": base64.b64encode(dados).decode()})
        except Exception:
            pass

    def ssh_fechar(self, sid):
        try:
            self.no.enviar_mensagem(self.numero, {"tipo": "ssh_fechar", "session_id": sid})
        except Exception:
            pass
        self.ssh_cb.pop(sid, None)


gerenciador = GerenciadorRequisicoes()


def ao_mudar_amigo(numero, status):
    if numero == gerenciador.numero and status == 0:
        gerenciador.lista_ok = False


no_tox = NoTox(ARQ_SAVEDATA, gerenciador.despachar, ao_mudar_amigo)
gerenciador.no = no_tox
no_tox.iniciar_loop()


def tentar_conectar_sessao():
    sessao = carregar_sessao()
    if not sessao:
        return False
    try:
        gerenciador.numero = no_tox.adicionar_amigo_por_endereco(sessao["endereco"])
        return True
    except Exception as e:
        log(f"Erro reconectando sessao: {e}")
        return False


def loop_bootstrap():
    ultimo = 0
    while True:
        try:
            nos = obter_nos_bootstrap()
            if not nos:
                atualizar_nos_bootstrap_online()
                nos = obter_nos_bootstrap()
            if nos and (no_tox.status_rede() == 0 or time.time() - ultimo > 1800):
                no_tox.bootstrap(nos)
                ultimo = time.time()
        except Exception as e:
            log(f"loop_bootstrap: {e}")
        time.sleep(30)


def loop_lista():
    """Mantém a lista de serviços atualizada sem bloquear a página."""
    estava = False
    while True:
        try:
            if gerenciador.numero is None:
                tentar_conectar_sessao()
            ok = gerenciador.conectado()
            if ok and (not estava or time.time() - gerenciador.lista_ts > 20):
                gerenciador.solicitar_lista()
            estava = ok
        except Exception as e:
            log(f"loop_lista: {e}")
        time.sleep(2)


tentar_conectar_sessao()
threading.Thread(target=loop_bootstrap, daemon=True).start()
threading.Thread(target=loop_lista, daemon=True).start()

# =====================================================================
# FLASK
# =====================================================================
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"),
            static_folder=str(BASE_DIR / "static"))
sock = Sock(app)
import logging as _logging
_logging.getLogger("werkzeug").setLevel(_logging.ERROR)

HOSTS_UI = {f"127.0.0.1:{PORTA}", f"localhost:{PORTA}"}


def _servico_do_host(host):
    """s-<id>.localhost[:porta] -> <id>"""
    h = host.split(":")[0]
    if h.startswith("s-") and h.endswith(".localhost"):
        return h[2:-len(".localhost")]
    return None


def _reescrever_location(v):
    """Redirect para o IP/host interno do servidor -> caminho relativo."""
    try:
        p = urlparse(v)
        if p.scheme not in ("http", "https") or not p.hostname:
            return v
        try:
            ip = ipaddress.ip_address(p.hostname)
            local = ip.is_loopback or ip.is_private
        except ValueError:
            local = p.hostname.lower() == "localhost"
        if not local:
            return v
        rel = p.path or "/"
        if p.query:
            rel += "?" + p.query
        return rel
    except Exception:
        return v


def _cabecalhos_resposta(brutos):
    pares = brutos.items() if isinstance(brutos, dict) else (brutos or [])
    pular = {"content-length", "transfer-encoding", "connection", "keep-alive",
             "strict-transport-security"}
    saida = []
    for par in pares:
        try:
            k, v = par[0], str(par[1])
        except Exception:
            continue
        kl = str(k).lower()
        if kl in pular:
            continue
        if kl == "location":
            v = _reescrever_location(v)
        elif kl == "set-cookie":
            v = re.sub(r';\s*Secure', '', v, flags=re.I)
            v = re.sub(r';\s*Domain=[^;]*', '', v, flags=re.I)
            v = re.sub(r'SameSite=None', 'SameSite=Lax', v, flags=re.I)
        saida.append((k, v))
    return saida


def _proxy(service_id):
    if not gerenciador.conectado():
        return "Sem conexao com o servidor remoto (Tox offline)", 502
    caminho = request.path
    if request.query_string:
        caminho += "?" + request.query_string.decode("latin-1")
    ocultos = {"host", "content-length", "accept-encoding", "connection",
               "origin", "referer", "upgrade", "keep-alive", "te"}
    cab = {k: v for k, v in request.headers.items() if k.lower() not in ocultos}
    resp = gerenciador.http_request(service_id, request.method, caminho, cab,
                                    request.get_data())
    try:
        corpo = base64.b64decode(resp.get("body", "")) if resp.get("body") else b""
    except Exception:
        corpo = b""
    return Response(corpo, status=resp.get("status", 502),
                    headers=_cabecalhos_resposta(resp.get("headers")))


@app.before_request
def guardas():
    host = (request.host or "").lower()
    sid = _servico_do_host(host)
    if sid:
        return _proxy(sid)
    if host not in HOSTS_UI:
        return "Host invalido", 400
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        origem = request.headers.get("Origin")
        if origem and urlparse(origem).netloc.lower() != host:
            return "Origem invalida", 403


@app.route("/")
def index():
    if not carregar_sessao():
        return redirect(url_for("login"))
    return render_template("dashboard.html")


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/api/login", methods=["POST"])
def api_login():
    dados = request.get_json(force=True, silent=True) or {}
    endereco = str(dados.get("endereco", "")).strip().upper()
    if not RE_ADDR.match(endereco):
        return jsonify({"ok": False, "erro": "ID Tox deve ter 76 caracteres hexadecimais"}), 400
    try:
        gerenciador.lista_ok = False
        gerenciador.lista = []
        gerenciador.numero = no_tox.adicionar_amigo_por_endereco(endereco)
        salvar_sessao({"endereco": endereco})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "erro": str(e)}), 400


@app.route("/api/logout", methods=["POST"])
def api_logout():
    excluir_sessao()
    if gerenciador.numero is not None:
        try:
            no_tox.remover_amigo(gerenciador.numero)
        except Exception as e:
            log(f"logout: {e}")
    gerenciador.numero = None
    gerenciador.lista, gerenciador.lista_ok = [], False
    return jsonify({"ok": True})


@app.route("/api/estado")
def api_estado():
    sessao = carregar_sessao() or {}
    rede = no_tox.status_rede()
    return jsonify({
        "sessao": bool(sessao),
        "servidor_id": (sessao.get("endereco", "")[:16] + "…") if sessao else "",
        "conectado": gerenciador.conectado(),
        "status_rede": rede,
        "rede_texto": {0: "Offline", 1: "Conectado (TCP)", 2: "Conectado (UDP)"}.get(rede, "?"),
        "meu_id": no_tox.endereco_hex(),
        "servicos": gerenciador.lista if gerenciador.conectado() else [],
        "lista_ok": gerenciador.lista_ok and gerenciador.conectado(),
        "nos_bootstrap": len(obter_nos_bootstrap()),
        "porta": PORTA,
    })


@app.route("/api/status")
def api_status():
    return jsonify({"conectado": gerenciador.conectado(),
                    "status_rede": no_tox.status_rede()})


@app.route("/api/bootstrap/atualizar", methods=["POST"])
def api_atualizar_bootstrap():
    ok, qtd = atualizar_nos_bootstrap_online()
    if ok:
        no_tox.bootstrap(obter_nos_bootstrap())
    return jsonify({"ok": ok, "novos": qtd})


@sock.route("/ws/ssh")
def ws_ssh(ws):
    origem = request.headers.get("Origin", "")
    if urlparse(origem).netloc.lower() != (request.host or "").lower():
        return   # bloqueia WebSocket vindo de outro site

    def enviar(obj):
        try:
            ws.send(json.dumps(obj))
        except Exception:
            parar.set()

    parar = threading.Event()
    if not gerenciador.conectado():
        enviar({"tipo": "erro", "mensagem": "sem conexao com o servidor"})
        return
    primeira = ws.receive(timeout=30)
    if not primeira:
        return
    try:
        inicio = json.loads(primeira)
    except Exception:
        return

    sid = str(uuid.uuid4())
    fila = queue.Queue()
    try:
        gerenciador.ssh_abrir(sid, inicio.get("usuario"), inicio.get("senha"), fila.put)
    except Exception as e:
        enviar({"tipo": "erro", "mensagem": f"Falha ao contatar o servidor: {e}"})
        return

    def para_navegador():
        while not parar.is_set():
            try:
                msg = fila.get(timeout=1)
            except queue.Empty:
                continue
            t = msg.get("tipo")
            if t == "ssh_dados":
                enviar({"tipo": "dados", "dados": msg["dados"]})
            elif t == "ssh_aberto":
                enviar({"tipo": "conectado"})
            elif t == "ssh_erro":
                enviar({"tipo": "erro", "mensagem": msg.get("mensagem")})
                parar.set()
            elif t == "ssh_fechado":
                enviar({"tipo": "fechado"})
                parar.set()

    threading.Thread(target=para_navegador, daemon=True).start()
    try:
        while not parar.is_set():
            rec = ws.receive(timeout=1)
            if rec is None:
                continue
            d = json.loads(rec)
            if d.get("tipo") == "tecla":
                gerenciador.ssh_dados(sid, d["dados"].encode())
            elif d.get("tipo") == "fechar":
                break
    except Exception:
        pass
    finally:
        parar.set()
        gerenciador.ssh_fechar(sid)


def main():
    log("Cliente de acesso remoto via Tox iniciado.")
    app.run(host="127.0.0.1", port=PORTA, debug=False, use_reloader=False, threaded=True)


if __name__ == "__main__":
    main()
