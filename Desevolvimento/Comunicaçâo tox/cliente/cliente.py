#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 CLIENTE DE ACESSO REMOTO VIA PROTOCOLO TOX (PAINEL PORTA 2100)
=====================================================================
"""

import os, sys, json, time, uuid, struct, secrets, threading, math, base64, queue
import ctypes, ctypes.util
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, render_template, redirect, url_for, Response

try:
    from flask_sock import Sock
except ImportError:
    print("Instale: pip install flask-sock"); sys.exit(1)

# =====================================================================
BASE_DIR = Path(__file__).resolve().parent
DADOS_DIR = BASE_DIR / "dados"
SESSAO_DIR = DADOS_DIR / "sessao"
CONFIG_DIR = DADOS_DIR / "config"
LOG_DIR = DADOS_DIR / "logs"
for d in (DADOS_DIR, SESSAO_DIR, CONFIG_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

ARQ_SAVEDATA = SESSAO_DIR / "identidade.tox"
ARQ_SERVIDOR = SESSAO_DIR / "servidor.json"
ARQ_BOOTSTRAP = CONFIG_DIR / "nos_bootstrap.json"
ARQ_LOG = LOG_DIR / "cliente.log"

def log(msg):
    linha = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(linha)
    try:
        with open(ARQ_LOG, "a", encoding="utf-8") as f: f.write(linha + "\n")
    except Exception: pass

def carregar_json(caminho, padrao):
    if caminho.exists():
        try:
            with open(caminho, "r", encoding="utf-8") as f: return json.load(f)
        except Exception: return padrao
    return padrao

def salvar_json(caminho, dados):
    with open(caminho, "w", encoding="utf-8") as f: json.dump(dados, f, ensure_ascii=False, indent=2)

# =====================================================================
# NÓS DE BOOTSTRAP (mesmo conceito do servidor)
# =====================================================================
NOS_BOOTSTRAP_PADRAO = [
    {"ip": "85.172.30.117", "porta": 33445,
     "chave_publica": "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698B2", "origem": "padrao"},
    {"ip": "46.101.197.175", "porta": 33445,
     "chave_publica": "CD133B521159541FB1D326DE9850F5E56A6C724B5B5E5F7BAEA6EDD6C8F8C3D", "origem": "padrao"},
    {"ip": "144.217.167.73", "porta": 33445,
     "chave_publica": "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A7373C6D", "origem": "padrao"},
    {"ip": "198.98.51.198", "porta": 33445,
     "chave_publica": "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931F1D0724D5C9537A5A4", "origem": "padrao"},
]

def obter_nos_bootstrap():
    nos = carregar_json(ARQ_BOOTSTRAP, None)
    if nos is None:
        salvar_json(ARQ_BOOTSTRAP, NOS_BOOTSTRAP_PADRAO)
        return list(NOS_BOOTSTRAP_PADRAO)
    return nos

def salvar_nos_bootstrap(nos):
    salvar_json(ARQ_BOOTSTRAP, nos)

def atualizar_nos_bootstrap_online():
    import urllib.request
    try:
        req = urllib.request.Request("https://nodes.tox.chat/json", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=8) as resp:
            dados = json.loads(resp.read().decode("utf-8"))
        novos = []
        for item in dados.get("nodes", []):
            if not item.get("status_udp"): continue
            ip = item.get("ipv4")
            if not ip or ip == "-": continue
            novos.append({"ip": ip, "porta": item.get("port", 33445),
                          "chave_publica": item.get("public_key", "").upper(), "origem": "nodes.tox.chat"})
        if novos:
            atuais = obter_nos_bootstrap()
            existentes = {(n["ip"], n["porta"]) for n in atuais}
            for n in novos:
                if (n["ip"], n["porta"]) not in existentes: atuais.append(n)
            salvar_nos_bootstrap(atuais)
            return True, len(novos)
        return False, 0
    except Exception as e:
        log(f"Falha ao atualizar bootstrap: {e}")
        return False, 0

def carregar_sessao():
    return carregar_json(ARQ_SERVIDOR, None)

def salvar_sessao(dados):
    salvar_json(ARQ_SERVIDOR, dados)
    try: os.chmod(ARQ_SERVIDOR, 0o600)
    except Exception: pass

def excluir_sessao():
    if ARQ_SERVIDOR.exists(): ARQ_SERVIDOR.unlink()

# =====================================================================
# LIGAÇÃO COM LIBTOXCORE (idêntica ao servidor)
# =====================================================================
TOX_ADDRESS_SIZE = 38
TOX_PUBLIC_KEY_SIZE = 32
TOX_SAVEDATA_TYPE_NONE = 0
TOX_SAVEDATA_TYPE_TOX_SAVE = 1
PACOTE_ID_DADOS = 160
MAX_FRAGMENTO = 1200

def carregar_libtoxcore():
    nomes = ["libtoxcore.so", "libtoxcore.so.2", "libtoxcore.so.1", "libtoxcore.so.0"]
    caminho = ctypes.util.find_library("toxcore")
    if caminho: nomes.insert(0, caminho)
    erro_final = None
    for nome in nomes:
        try: return ctypes.CDLL(nome)
        except OSError as e: erro_final = e
    raise RuntimeError(f"Nao foi possivel carregar libtoxcore. Compile o c-toxcore. Erro: {erro_final}")

def configurar_assinaturas(lib):
    c_void_p = ctypes.c_void_p; c_int = ctypes.c_int
    c_uint8_p = ctypes.POINTER(ctypes.c_uint8)
    c_uint32 = ctypes.c_uint32; c_uint16 = ctypes.c_uint16
    c_size_t = ctypes.c_size_t; c_bool = ctypes.c_bool; c_char_p = ctypes.c_char_p

    lib.tox_options_new.restype = c_void_p; lib.tox_options_new.argtypes = [ctypes.POINTER(c_int)]
    lib.tox_options_free.restype = None; lib.tox_options_free.argtypes = [c_void_p]
    lib.tox_options_set_ipv6_enabled.restype = None; lib.tox_options_set_ipv6_enabled.argtypes = [c_void_p, c_bool]
    lib.tox_options_set_udp_enabled.restype = None; lib.tox_options_set_udp_enabled.argtypes = [c_void_p, c_bool]
    lib.tox_options_set_local_discovery_enabled.restype = None; lib.tox_options_set_local_discovery_enabled.argtypes = [c_void_p, c_bool]
    lib.tox_options_set_savedata_type.restype = None; lib.tox_options_set_savedata_type.argtypes = [c_void_p, c_int]
    lib.tox_options_set_savedata_data.restype = None; lib.tox_options_set_savedata_data.argtypes = [c_void_p, c_uint8_p, c_size_t]
    lib.tox_new.restype = c_void_p; lib.tox_new.argtypes = [c_void_p, ctypes.POINTER(c_int)]
    lib.tox_kill.restype = None; lib.tox_kill.argtypes = [c_void_p]
    lib.tox_bootstrap.restype = c_bool; lib.tox_bootstrap.argtypes = [c_void_p, c_char_p, c_uint16, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_iteration_interval.restype = c_uint32; lib.tox_iteration_interval.argtypes = [c_void_p]
    lib.tox_iterate.restype = None; lib.tox_iterate.argtypes = [c_void_p, c_void_p]
    lib.tox_self_get_address.restype = None; lib.tox_self_get_address.argtypes = [c_void_p, c_uint8_p]
    lib.tox_self_get_public_key.restype = None; lib.tox_self_get_public_key.argtypes = [c_void_p, c_uint8_p]
    lib.tox_self_get_nospam.restype = c_uint32; lib.tox_self_get_nospam.argtypes = [c_void_p]
    lib.tox_self_set_nospam.restype = None; lib.tox_self_set_nospam.argtypes = [c_void_p, c_uint32]
    lib.tox_self_get_connection_status.restype = c_int; lib.tox_self_get_connection_status.argtypes = [c_void_p]
    lib.tox_get_savedata_size.restype = c_size_t; lib.tox_get_savedata_size.argtypes = [c_void_p]
    lib.tox_get_savedata.restype = None; lib.tox_get_savedata.argtypes = [c_void_p, c_uint8_p]
    lib.tox_friend_add.restype = c_uint32; lib.tox_friend_add.argtypes = [c_void_p, c_uint8_p, c_uint8_p, c_size_t, ctypes.POINTER(c_int)]
    lib.tox_friend_add_norequest.restype = c_uint32; lib.tox_friend_add_norequest.argtypes = [c_void_p, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_friend_delete.restype = c_bool; lib.tox_friend_delete.argtypes = [c_void_p, c_uint32, ctypes.POINTER(c_int)]
    lib.tox_friend_get_public_key.restype = c_bool; lib.tox_friend_get_public_key.argtypes = [c_void_p, c_uint32, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_friend_by_public_key.restype = c_uint32; lib.tox_friend_by_public_key.argtypes = [c_void_p, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_friend_get_connection_status.restype = c_int; lib.tox_friend_get_connection_status.argtypes = [c_void_p, c_uint32, ctypes.POINTER(c_int)]
    lib.tox_friend_send_lossless_packet.restype = c_bool; lib.tox_friend_send_lossless_packet.argtypes = [c_void_p, c_uint32, c_uint8_p, c_size_t, ctypes.POINTER(c_int)]
    lib.tox_self_get_friend_list_size.restype = c_size_t; lib.tox_self_get_friend_list_size.argtypes = [c_void_p]
    lib.tox_self_get_friend_list.restype = None; lib.tox_self_get_friend_list.argtypes = [c_void_p, ctypes.POINTER(c_uint32)]
    lib.tox_callback_self_connection_status.restype = None; lib.tox_callback_self_connection_status.argtypes = [c_void_p, c_void_p]
    lib.tox_callback_friend_request.restype = None; lib.tox_callback_friend_request.argtypes = [c_void_p, c_void_p]
    lib.tox_callback_friend_connection_status.restype = None; lib.tox_callback_friend_connection_status.argtypes = [c_void_p, c_void_p]
    lib.tox_callback_friend_lossless_packet.restype = None; lib.tox_callback_friend_lossless_packet.argtypes = [c_void_p, c_void_p]


class NoTox:
    def __init__(self, caminho_savedata: Path, auto_aceitar_amigos: bool, log_fn=log):
        self.lib = carregar_libtoxcore()
        configurar_assinaturas(self.lib)
        self.caminho_savedata = caminho_savedata
        self.auto_aceitar_amigos = auto_aceitar_amigos
        self.log = log_fn
        self.tox = None
        self._rodando = False
        self._trava = threading.RLock()
        self._amigos = {}
        self._buffers_fragmentos = {}
        self._refs_callbacks = []
        self._callback_mensagem = None
        self._criar_tox()

    def definir_callback_mensagem(self, func): self._callback_mensagem = func

    def _criar_tox(self):
        with self._trava:
            erro = ctypes.c_int(0)
            opcoes = self.lib.tox_options_new(ctypes.byref(erro))
            if not opcoes: raise RuntimeError("Falha ao criar Tox_Options")
            self.lib.tox_options_set_ipv6_enabled(opcoes, True)
            self.lib.tox_options_set_udp_enabled(opcoes, True)
            self.lib.tox_options_set_local_discovery_enabled(opcoes, True)

            dados_salvos = None
            if self.caminho_savedata.exists():
                dados_salvos = self.caminho_savedata.read_bytes()
            buffer_savedata = None
            if dados_salvos:
                self.lib.tox_options_set_savedata_type(opcoes, TOX_SAVEDATA_TYPE_TOX_SAVE)
                buffer_savedata = (ctypes.c_uint8 * len(dados_salvos)).from_buffer_copy(dados_salvos)
                self.lib.tox_options_set_savedata_data(opcoes, buffer_savedata, len(dados_salvos))
            else:
                self.lib.tox_options_set_savedata_type(opcoes, TOX_SAVEDATA_TYPE_NONE)

            erro_new = ctypes.c_int(0)
            self.tox = self.lib.tox_new(opcoes, ctypes.byref(erro_new))
            self.lib.tox_options_free(opcoes)
            if not self.tox: raise RuntimeError(f"Falha ao criar Tox (codigo {erro_new.value})")

            self._registrar_callbacks()
            self._carregar_amigos_existentes()
            self._salvar_estado_sem_trava()
        self.log(f"[Tox] Identidade cliente pronta. ID: {self.obter_endereco_hex()}")

    def _registrar_callbacks(self):
        c_void_p = ctypes.c_void_p
        CB_SELF_CONN = ctypes.CFUNCTYPE(None, c_void_p, ctypes.c_int, c_void_p)
        CB_FRIEND_REQ = ctypes.CFUNCTYPE(None, c_void_p, ctypes.POINTER(ctypes.c_uint8),
                                          ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, c_void_p)
        CB_FRIEND_CONN = ctypes.CFUNCTYPE(None, c_void_p, ctypes.c_uint32, ctypes.c_int, c_void_p)
        CB_FRIEND_PKT = ctypes.CFUNCTYPE(None, c_void_p, ctypes.c_uint32,
                                          ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, c_void_p)

        def ao_mudar_conexao_propria(tox, status, user_data):
            nomes = {0: "Offline", 1: "Conectado(TCP)", 2: "Conectado(UDP)"}
            self.log(f"[Tox] Status da rede: {nomes.get(status, status)}")

        def ao_receber_pedido_amizade(tox, chave_ptr, msg_ptr, tamanho, user_data):
            chave_publica = bytes(ctypes.cast(chave_ptr, ctypes.POINTER(ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)).contents)
            self.log(f"[Tox] Pedido de amizade recebido mas ignorado (modo cliente): {chave_publica.hex()[:16]}...")

        def ao_mudar_conexao_amigo(tox, numero_amigo, status, user_data):
            info = self._amigos.setdefault(numero_amigo, {})
            info["status"] = status
            nomes = {0: "desconectado", 1: "conectado(TCP)", 2: "conectado(UDP)"}
            self.log(f"[Tox] Servidor (amigo {numero_amigo}): {nomes.get(status, status)}")

        def ao_receber_pacote(tox, numero_amigo, dados_ptr, tamanho, user_data):
            try:
                bruto = bytes(ctypes.cast(dados_ptr, ctypes.POINTER(ctypes.c_uint8 * tamanho)).contents)
            except Exception:
                return
            self._processar_fragmento(numero_amigo, bruto)

        self._cb_self_conn = CB_SELF_CONN(ao_mudar_conexao_propria)
        self._cb_friend_req = CB_FRIEND_REQ(ao_receber_pedido_amizade)
        self._cb_friend_conn = CB_FRIEND_CONN(ao_mudar_conexao_amigo)
        self._cb_friend_pkt = CB_FRIEND_PKT(ao_receber_pacote)
        self._refs_callbacks += [self._cb_self_conn, self._cb_friend_req, self._cb_friend_conn, self._cb_friend_pkt]

        self.lib.tox_callback_self_connection_status(self.tox, self._cb_self_conn)
        self.lib.tox_callback_friend_request(self.tox, self._cb_friend_req)
        self.lib.tox_callback_friend_connection_status(self.tox, self._cb_friend_conn)
        self.lib.tox_callback_friend_lossless_packet(self.tox, self._cb_friend_pkt)

    def _carregar_amigos_existentes(self):
        tamanho = self.lib.tox_self_get_friend_list_size(self.tox)
        if tamanho == 0: return
        buf = (ctypes.c_uint32 * tamanho)()
        self.lib.tox_self_get_friend_list(self.tox, buf)
        for numero in buf:
            erro = ctypes.c_int(0)
            chave_buf = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)()
            ok = self.lib.tox_friend_get_public_key(self.tox, numero, chave_buf, ctypes.byref(erro))
            chave_hex = bytes(chave_buf).hex() if ok else ""
            self._amigos[numero] = {"chave_publica": chave_hex, "status": 0}

    def _processar_fragmento(self, numero_amigo, bruto: bytes):
        if len(bruto) < 9 or bruto[0] != PACOTE_ID_DADOS: return
        frame_id = bruto[1:5]
        idx = struct.unpack(">H", bruto[5:7])[0]
        total = struct.unpack(">H", bruto[7:9])[0]
        payload = bruto[9:]
        chave_buf = (numero_amigo, frame_id)
        buf = self._buffers_fragmentos.setdefault(chave_buf, {})
        buf[idx] = payload
        if len(buf) >= total:
            partes = [buf[i] for i in range(total)]
            completo = b"".join(partes)
            del self._buffers_fragmentos[chave_buf]
            try:
                mensagem = json.loads(completo.decode("utf-8"))
            except Exception:
                return
            if self._callback_mensagem:
                threading.Thread(target=self._callback_mensagem, args=(numero_amigo, mensagem), daemon=True).start()

    def enviar_mensagem(self, numero_amigo: int, mensagem: dict):
        bruto = json.dumps(mensagem).encode("utf-8")
        frame_id = secrets.token_bytes(4)
        total = max(1, math.ceil(len(bruto) / MAX_FRAGMENTO))
        for idx in range(total):
            pedaco = bruto[idx*MAX_FRAGMENTO:(idx+1)*MAX_FRAGMENTO]
            cabecalho = bytes([PACOTE_ID_DADOS]) + frame_id + struct.pack(">H", idx) + struct.pack(">H", total)
            dados_envio = cabecalho + pedaco
            buf = (ctypes.c_uint8 * len(dados_envio)).from_buffer_copy(dados_envio)
            erro = ctypes.c_int(0)
            with self._trava:
                ok = self.lib.tox_friend_send_lossless_packet(self.tox, numero_amigo, buf, len(dados_envio), ctypes.byref(erro))
            if not ok:
                raise RuntimeError(f"Falha ao enviar pacote Tox (codigo {erro.value})")

    def iniciar_loop(self):
        self._rodando = True
        threading.Thread(target=self._loop, daemon=True).start()
        threading.Thread(target=self._loop_salvar_periodico, daemon=True).start()
        threading.Thread(target=self._loop_bootstrap_periodico, daemon=True).start()

    def _loop(self):
        while self._rodando:
            with self._trava:
                self.lib.tox_iterate(self.tox, None)
                intervalo = self.lib.tox_iteration_interval(self.tox)
            time.sleep(max(intervalo, 10) / 1000.0)

    def _loop_salvar_periodico(self):
        while self._rodando:
            time.sleep(20)
            try: self._salvar_estado()
            except Exception as e: self.log(f"[Tox] Erro salvando estado: {e}")

    def _loop_bootstrap_periodico(self):
        while self._rodando:
            try: self.bootstrap(obter_nos_bootstrap())
            except Exception as e: self.log(f"[Tox] Erro bootstrap periodico: {e}")
            time.sleep(1800)

    def bootstrap(self, nos: list):
        for no in nos:
            try:
                chave = bytes.fromhex(no["chave_publica"])
                buf = (ctypes.c_uint8 * len(chave)).from_buffer_copy(chave)
                erro = ctypes.c_int(0)
                with self._trava:
                    self.lib.tox_bootstrap(self.tox, no["ip"].encode(), int(no["porta"]), buf, ctypes.byref(erro))
            except Exception as e:
                self.log(f"[Tox] Erro bootstrap {no}: {e}")

    def _salvar_estado(self):
        with self._trava: self._salvar_estado_sem_trava()

    def _salvar_estado_sem_trava(self):
        tamanho = self.lib.tox_get_savedata_size(self.tox)
        buffer = (ctypes.c_uint8 * tamanho)()
        self.lib.tox_get_savedata(self.tox, buffer)
        dados = bytes(buffer)
        tmp = self.caminho_savedata.with_suffix(".tmp")
        tmp.write_bytes(dados)
        tmp.replace(self.caminho_savedata)

    def obter_endereco_hex(self) -> str:
        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE)()
        with self._trava: self.lib.tox_self_get_address(self.tox, buf)
        return bytes(buf).hex().upper()

    def status_rede(self) -> int:
        with self._trava: return self.lib.tox_self_get_connection_status(self.tox)

    def adicionar_amigo_por_endereco(self, endereco_hex: str, mensagem=b"Solicitando acesso remoto"):
        endereco_bytes = bytes.fromhex(endereco_hex.strip())
        if len(endereco_bytes) != TOX_ADDRESS_SIZE:
            raise ValueError("Endereco Tox invalido (tamanho incorreto)")
        chave_publica = endereco_bytes[:TOX_PUBLIC_KEY_SIZE]
        chave_publica_hex = chave_publica.hex()

        with self._trava:
            erro_busca = ctypes.c_int(0)
            buf_pub = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE).from_buffer_copy(chave_publica)
            numero_existente = self.lib.tox_friend_by_public_key(self.tox, buf_pub, ctypes.byref(erro_busca))
            if erro_busca.value == 0:
                self._amigos.setdefault(numero_existente, {"chave_publica": chave_publica_hex, "status": 0})
                return numero_existente

            buf_end = (ctypes.c_uint8 * TOX_ADDRESS_SIZE).from_buffer_copy(endereco_bytes)
            buf_msg = (ctypes.c_uint8 * len(mensagem)).from_buffer_copy(mensagem)
            erro = ctypes.c_int(0)
            numero = self.lib.tox_friend_add(self.tox, buf_end, buf_msg, len(mensagem), ctypes.byref(erro))
            if erro.value != 0:
                raise RuntimeError(f"Falha ao adicionar amigo (codigo {erro.value})")
        self._amigos[numero] = {"chave_publica": chave_publica_hex, "status": 0}
        self._salvar_estado()
        return numero

    def amigo_conectado(self, numero_amigo) -> bool:
        info = self._amigos.get(numero_amigo)
        return bool(info and info.get("status", 0) != 0)

    def parar(self):
        self._rodando = False
        try: self._salvar_estado()
        except Exception: pass
        with self._trava:
            if self.tox: self.lib.tox_kill(self.tox); self.tox = None


# =====================================================================
# GERENCIADOR DE REQUISIÇÕES (Request/Response sobre pacotes Tox)
# =====================================================================
class GerenciadorRequisicoes:
    def __init__(self, no_tox: NoTox):
        self.no_tox = no_tox
        self.numero_amigo_servidor = None
        self.pendentes = {}
        self.ssh_callbacks = {}
        self.ultima_lista_servicos = []
        self._evento_lista = None
        no_tox.definir_callback_mensagem(self._despachar)

    def _despachar(self, numero_amigo, msg):
        tipo = msg.get("tipo")
        if tipo == "http_response":
            evt = self.pendentes.get(msg["id"])
            if evt: evt["resposta"] = msg; evt["evento"].set()
        elif tipo in ("ssh_dados", "ssh_aberto", "ssh_erro", "ssh_fechado"):
            cb = self.ssh_callbacks.get(msg.get("session_id"))
            if cb: cb(msg)
        elif tipo == "lista_servicos":
            self.ultima_lista_servicos = msg.get("dados", [])
            if self._evento_lista: self._evento_lista.set()

    def conectado(self):
        return (self.numero_amigo_servidor is not None and
                self.no_tox.amigo_conectado(self.numero_amigo_servidor))

    def listar_servicos(self, timeout=10):
        if not self.conectado(): return []
        self._evento_lista = threading.Event()
        try:
            self.no_tox.enviar_mensagem(self.numero_amigo_servidor, {"tipo": "listar_servicos"})
        except Exception:
            return []
        if self._evento_lista.wait(timeout): return self.ultima_lista_servicos
        return []

    def http_request(self, service_id, method, path, headers, body, timeout=20):
        req_id = str(uuid.uuid4())
        evt = {"evento": threading.Event(), "resposta": None}
        self.pendentes[req_id] = evt
        try:
            self.no_tox.enviar_mensagem(self.numero_amigo_servidor, {
                "tipo": "http_request", "id": req_id, "service_id": service_id,
                "method": method, "path": path, "headers": headers,
                "body": base64.b64encode(body).decode() if body else ""
            })
        except Exception:
            self.pendentes.pop(req_id, None)
            return {"status": 502, "headers": {}, "body": ""}
        if evt["evento"].wait(timeout):
            self.pendentes.pop(req_id, None)
            return evt["resposta"]
        self.pendentes.pop(req_id, None)
        return {"status": 504, "headers": {}, "body": base64.b64encode(b"Timeout").decode()}

    def ssh_abrir(self, session_id, usuario, senha, callback):
        self.ssh_callbacks[session_id] = callback
        self.no_tox.enviar_mensagem(self.numero_amigo_servidor, {
            "tipo": "ssh_abrir", "session_id": session_id, "usuario": usuario, "senha": senha})

    def ssh_dados(self, session_id, dados: bytes):
        try:
            self.no_tox.enviar_mensagem(self.numero_amigo_servidor, {
                "tipo": "ssh_dados", "session_id": session_id, "dados": base64.b64encode(dados).decode()})
        except Exception: pass

    def ssh_fechar(self, session_id):
        try:
            self.no_tox.enviar_mensagem(self.numero_amigo_servidor, {"tipo": "ssh_fechar", "session_id": session_id})
        except Exception: pass
        self.ssh_callbacks.pop(session_id, None)

# =====================================================================
# INICIALIZAÇÃO
# =====================================================================
no_tox = NoTox(ARQ_SAVEDATA, auto_aceitar_amigos=False, log_fn=log)
no_tox.bootstrap(obter_nos_bootstrap())
no_tox.iniciar_loop()
gerenciador = GerenciadorRequisicoes(no_tox)

def tentar_conectar_sessao():
    sessao = carregar_sessao()
    if not sessao: return False
    try:
        numero = no_tox.adicionar_amigo_por_endereco(sessao["endereco"])
        gerenciador.numero_amigo_servidor = numero
        return True
    except Exception as e:
        log(f"Erro reconectando sessao: {e}")
        return False

tentar_conectar_sessao()

# =====================================================================
# FLASK
# =====================================================================
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))
sock = Sock(app)

@app.route("/")
def index():
    sessao = carregar_sessao()
    if not sessao:
        return redirect(url_for("login"))
    if gerenciador.numero_amigo_servidor is None:
        tentar_conectar_sessao()
    conectado = gerenciador.conectado()
    servicos = gerenciador.listar_servicos() if conectado else []
    return render_template("dashboard.html", servicos=servicos, conectado=conectado,
                            meu_id=no_tox.obter_endereco_hex(), status_rede=no_tox.status_rede())

@app.route("/login")
def login():
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def api_login():
    dados = request.get_json(force=True)
    endereco = dados.get("endereco", "").strip().upper()
    if len(endereco) != 76:
        return jsonify({"ok": False, "erro": "ID Tox deve ter 76 caracteres"}), 400
    try:
        numero = no_tox.adicionar_amigo_por_endereco(endereco)
        gerenciador.numero_amigo_servidor = numero
        salvar_sessao({"endereco": endereco})
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "erro": str(e)}), 400

@app.route("/api/logout", methods=["POST"])
def api_logout():
    excluir_sessao()
    gerenciador.numero_amigo_servidor = None
    return jsonify({"ok": True})

@app.route("/api/status")
def api_status():
    return jsonify({"conectado": gerenciador.conectado(), "status_rede": no_tox.status_rede()})

@app.route("/api/bootstrap/atualizar", methods=["POST"])
def api_atualizar_bootstrap():
    ok, qtd = atualizar_nos_bootstrap_online()
    return jsonify({"ok": ok, "novos": qtd})

@app.route("/proxy/<service_id>/", defaults={"subpath": ""}, methods=["GET","POST","PUT","DELETE","PATCH"])
@app.route("/proxy/<service_id>/<path:subpath>", methods=["GET","POST","PUT","DELETE","PATCH"])
def proxy(service_id, subpath):
    if not gerenciador.conectado():
        return "Sem conexao com o servidor remoto (Tox offline)", 502
    caminho = "/" + subpath
    if request.query_string: caminho += "?" + request.query_string.decode()
    cabecalhos = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}
    resp = gerenciador.http_request(service_id, request.method, caminho, cabecalhos, request.get_data())
    corpo = base64.b64decode(resp.get("body","")) if resp.get("body") else b""
    cab = [(k, v) for k, v in (resp.get("headers") or {}).items()
           if k.lower() not in ("content-encoding","transfer-encoding","connection")]
    return Response(corpo, status=resp.get("status", 502), headers=cab)

@sock.route("/ws/ssh")
def ws_ssh(ws):
    if not gerenciador.conectado():
        ws.send(json.dumps({"tipo":"erro","mensagem":"sem conexao com o servidor"}))
        return
    primeira = ws.receive()
    if not primeira: return
    try:
        inicio = json.loads(primeira)
    except Exception:
        return

    session_id = str(uuid.uuid4())
    fila = queue.Queue()
    parar = threading.Event()

    def callback(msg): fila.put(msg)
    gerenciador.ssh_abrir(session_id, inicio.get("usuario"), inicio.get("senha"), callback)

    def enviar_para_navegador():
        while not parar.is_set():
            try: msg = fila.get(timeout=1)
            except queue.Empty: continue
            tipo = msg.get("tipo")
            if tipo == "ssh_dados": ws.send(json.dumps({"tipo":"dados","dados": msg["dados"]}))
            elif tipo == "ssh_aberto": ws.send(json.dumps({"tipo":"conectado"}))
            elif tipo == "ssh_erro": ws.send(json.dumps({"tipo":"erro","mensagem": msg.get("mensagem")})); parar.set()
            elif tipo == "ssh_fechado": ws.send(json.dumps({"tipo":"fechado"})); parar.set()

    threading.Thread(target=enviar_para_navegador, daemon=True).start()

    try:
        while not parar.is_set():
            recebido = ws.receive(timeout=1)
            if recebido is None: continue
            dado = json.loads(recebido)
            if dado.get("tipo") == "tecla":
                gerenciador.ssh_dados(session_id, dado["dados"].encode())
            elif dado.get("tipo") == "fechar":
                break
    except Exception:
        pass
    finally:
        parar.set()
        gerenciador.ssh_fechar(session_id)

def main():
    log("Cliente de acesso remoto via Tox iniciado.")
    app.run(host="127.0.0.1", port=2100, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
