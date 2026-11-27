#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 SERVIDOR DE ACESSO REMOTO VIA PROTOCOLO TOX (PAINEL PORTA 2000)
=====================================================================
Usa libtoxcore real via ctypes. Não depende de IP público, atravessa
NAT via DHT/UDP hole punching ou retransmissores TCP do próprio Tox.
Funciona também em rede local sem internet (local discovery).
"""

import os, sys, json, time, uuid, struct, secrets, threading, math
import urllib.request, urllib.error
import ctypes, ctypes.util
from pathlib import Path
from datetime import datetime

from flask import Flask, request, jsonify, render_template

try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False

# =====================================================================
# CAMINHOS
# =====================================================================
BASE_DIR = Path(__file__).resolve().parent
DADOS_DIR = BASE_DIR / "dados"
CONFIG_DIR = DADOS_DIR / "config"
CHAVE_DIR = DADOS_DIR / "chave"
LOG_DIR = DADOS_DIR / "logs"

for d in (DADOS_DIR, CONFIG_DIR, CHAVE_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

ARQ_SAVEDATA = CHAVE_DIR / "identidade.tox"
ARQ_SERVICOS = CONFIG_DIR / "servicos.json"
ARQ_BOOTSTRAP = CONFIG_DIR / "nos_bootstrap.json"
ARQ_LOG = LOG_DIR / "acesso.log"

_trava_arquivos = threading.Lock()

def log(msg):
    linha = f"[{datetime.now().isoformat(timespec='seconds')}] {msg}"
    print(linha)
    try:
        with open(ARQ_LOG, "a", encoding="utf-8") as f:
            f.write(linha + "\n")
    except Exception:
        pass

def carregar_json(caminho, padrao):
    with _trava_arquivos:
        if caminho.exists():
            try:
                with open(caminho, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return padrao
        return padrao

def salvar_json(caminho, dados):
    with _trava_arquivos:
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump(dados, f, ensure_ascii=False, indent=2)

# =====================================================================
# NÓS DE BOOTSTRAP (LISTA DE IPS PARA ENTRAR NA REDE TOX)
# =====================================================================
# ATENÇÃO: estes nós podem ficar desatualizados. Use o botão
# "Atualizar lista" no painel sempre que tiver internet disponível.
NOS_BOOTSTRAP_PADRAO = [
    {"ip": "85.172.30.117", "porta": 33445,
     "chave_publica": "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698B2",
     "origem": "padrao"},
    {"ip": "46.101.197.175", "porta": 33445,
     "chave_publica": "CD133B521159541FB1D326DE9850F5E56A6C724B5B5E5F7BAEA6EDD6C8F8C3D",
     "origem": "padrao"},
    {"ip": "144.217.167.73", "porta": 33445,
     "chave_publica": "7E5668E0EE09E19F320AD47902419331FFEE147BB3606769CFBE921A7373C6D",
     "origem": "padrao"},
    {"ip": "198.98.51.198", "porta": 33445,
     "chave_publica": "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931F1D0724D5C9537A5A4",
     "origem": "padrao"},
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
    """Tenta buscar lista atual de nós públicos. Falha silenciosamente se offline."""
    try:
        req = urllib.request.Request(
            "https://nodes.tox.chat/json",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            dados = json.loads(resp.read().decode("utf-8"))
        novos = []
        for item in dados.get("nodes", []):
            if not item.get("status_udp"):
                continue
            ip = item.get("ipv4")
            if not ip or ip == "-":
                continue
            novos.append({
                "ip": ip, "porta": item.get("port", 33445),
                "chave_publica": item.get("public_key", "").upper(),
                "origem": "nodes.tox.chat"
            })
        if novos:
            atuais = obter_nos_bootstrap()
            existentes = {(n["ip"], n["porta"]) for n in atuais}
            for n in novos:
                if (n["ip"], n["porta"]) not in existentes:
                    atuais.append(n)
            salvar_nos_bootstrap(atuais)
            log(f"Lista de bootstrap atualizada: +{len(novos)} nós verificados online")
            return True, len(novos)
        return False, 0
    except Exception as e:
        log(f"Falha ao atualizar nós de bootstrap (sem internet?): {e}")
        return False, 0

# =====================================================================
# SERVIÇOS
# =====================================================================
def obter_servicos():
    padrao = [
        {"id": "builtin-ssh", "nome": "SSH", "tipo": "ssh", "host": "127.0.0.1",
         "porta": 22, "comentario": "Conectar ao servidor SSH", "ativo": False, "builtin": True},
        {"id": "builtin-admin", "nome": "Painel Admin", "tipo": "http", "host": "127.0.0.1",
         "porta": 2000, "comentario": "Acessar este painel remotamente", "ativo": False, "builtin": True},
    ]
    servicos = carregar_json(ARQ_SERVICOS, None)
    if servicos is None:
        salvar_json(ARQ_SERVICOS, padrao)
        return padrao
    return servicos

def salvar_servicos(servicos):
    salvar_json(ARQ_SERVICOS, servicos)

# =====================================================================
# LIGAÇÃO COM LIBTOXCORE VIA CTYPES
# =====================================================================
TOX_ADDRESS_SIZE = 38
TOX_PUBLIC_KEY_SIZE = 32
TOX_SAVEDATA_TYPE_NONE = 0
TOX_SAVEDATA_TYPE_TOX_SAVE = 1
PACOTE_ID_DADOS = 160          # faixa reservada (160-191) para pacotes lossless customizados
MAX_FRAGMENTO = 1200           # abaixo do limite TOX_MAX_CUSTOM_PACKET_SIZE (1373)

def carregar_libtoxcore():
    nomes = ["libtoxcore.so", "libtoxcore.so.2", "libtoxcore.so.1", "libtoxcore.so.0"]
    caminho = ctypes.util.find_library("toxcore")
    if caminho:
        nomes.insert(0, caminho)
    erro_final = None
    for nome in nomes:
        try:
            return ctypes.CDLL(nome)
        except OSError as e:
            erro_final = e
    raise RuntimeError(
        "Não foi possível carregar libtoxcore. Compile o c-toxcore primeiro "
        f"(veja instruções). Erro técnico: {erro_final}"
    )

def configurar_assinaturas(lib):
    c_void_p = ctypes.c_void_p
    c_int = ctypes.c_int
    c_uint8_p = ctypes.POINTER(ctypes.c_uint8)
    c_uint32 = ctypes.c_uint32
    c_uint16 = ctypes.c_uint16
    c_size_t = ctypes.c_size_t
    c_bool = ctypes.c_bool
    c_char_p = ctypes.c_char_p

    lib.tox_options_new.restype = c_void_p
    lib.tox_options_new.argtypes = [ctypes.POINTER(c_int)]
    lib.tox_options_free.restype = None
    lib.tox_options_free.argtypes = [c_void_p]
    lib.tox_options_set_ipv6_enabled.restype = None
    lib.tox_options_set_ipv6_enabled.argtypes = [c_void_p, c_bool]
    lib.tox_options_set_udp_enabled.restype = None
    lib.tox_options_set_udp_enabled.argtypes = [c_void_p, c_bool]
    lib.tox_options_set_local_discovery_enabled.restype = None
    lib.tox_options_set_local_discovery_enabled.argtypes = [c_void_p, c_bool]
    lib.tox_options_set_savedata_type.restype = None
    lib.tox_options_set_savedata_type.argtypes = [c_void_p, c_int]
    lib.tox_options_set_savedata_data.restype = None
    lib.tox_options_set_savedata_data.argtypes = [c_void_p, c_uint8_p, c_size_t]

    lib.tox_new.restype = c_void_p
    lib.tox_new.argtypes = [c_void_p, ctypes.POINTER(c_int)]
    lib.tox_kill.restype = None
    lib.tox_kill.argtypes = [c_void_p]

    lib.tox_bootstrap.restype = c_bool
    lib.tox_bootstrap.argtypes = [c_void_p, c_char_p, c_uint16, c_uint8_p, ctypes.POINTER(c_int)]

    lib.tox_iteration_interval.restype = c_uint32
    lib.tox_iteration_interval.argtypes = [c_void_p]
    lib.tox_iterate.restype = None
    lib.tox_iterate.argtypes = [c_void_p, c_void_p]

    lib.tox_self_get_address.restype = None
    lib.tox_self_get_address.argtypes = [c_void_p, c_uint8_p]
    lib.tox_self_get_public_key.restype = None
    lib.tox_self_get_public_key.argtypes = [c_void_p, c_uint8_p]
    lib.tox_self_get_nospam.restype = c_uint32
    lib.tox_self_get_nospam.argtypes = [c_void_p]
    lib.tox_self_set_nospam.restype = None
    lib.tox_self_set_nospam.argtypes = [c_void_p, c_uint32]
    lib.tox_self_get_connection_status.restype = c_int
    lib.tox_self_get_connection_status.argtypes = [c_void_p]

    lib.tox_get_savedata_size.restype = c_size_t
    lib.tox_get_savedata_size.argtypes = [c_void_p]
    lib.tox_get_savedata.restype = None
    lib.tox_get_savedata.argtypes = [c_void_p, c_uint8_p]

    lib.tox_friend_add.restype = c_uint32
    lib.tox_friend_add.argtypes = [c_void_p, c_uint8_p, c_uint8_p, c_size_t, ctypes.POINTER(c_int)]
    lib.tox_friend_add_norequest.restype = c_uint32
    lib.tox_friend_add_norequest.argtypes = [c_void_p, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_friend_delete.restype = c_bool
    lib.tox_friend_delete.argtypes = [c_void_p, c_uint32, ctypes.POINTER(c_int)]
    lib.tox_friend_get_public_key.restype = c_bool
    lib.tox_friend_get_public_key.argtypes = [c_void_p, c_uint32, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_friend_by_public_key.restype = c_uint32
    lib.tox_friend_by_public_key.argtypes = [c_void_p, c_uint8_p, ctypes.POINTER(c_int)]
    lib.tox_friend_get_connection_status.restype = c_int
    lib.tox_friend_get_connection_status.argtypes = [c_void_p, c_uint32, ctypes.POINTER(c_int)]
    lib.tox_friend_send_lossless_packet.restype = c_bool
    lib.tox_friend_send_lossless_packet.argtypes = [c_void_p, c_uint32, c_uint8_p, c_size_t, ctypes.POINTER(c_int)]
    lib.tox_self_get_friend_list_size.restype = c_size_t
    lib.tox_self_get_friend_list_size.argtypes = [c_void_p]
    lib.tox_self_get_friend_list.restype = None
    lib.tox_self_get_friend_list.argtypes = [c_void_p, ctypes.POINTER(c_uint32)]

    lib.tox_callback_self_connection_status.restype = None
    lib.tox_callback_self_connection_status.argtypes = [c_void_p, c_void_p]
    lib.tox_callback_friend_request.restype = None
    lib.tox_callback_friend_request.argtypes = [c_void_p, c_void_p]
    lib.tox_callback_friend_connection_status.restype = None
    lib.tox_callback_friend_connection_status.argtypes = [c_void_p, c_void_p]
    lib.tox_callback_friend_lossless_packet.restype = None
    lib.tox_callback_friend_lossless_packet.argtypes = [c_void_p, c_void_p]


class NoTox:
    """
    Encapsula uma identidade Tox (servidor ou cliente).
    Todas as chamadas à libtoxcore são serializadas com uma trava,
    pois a biblioteca não é thread-safe.
    """
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

    def definir_callback_mensagem(self, func):
        self._callback_mensagem = func

    def _criar_tox(self):
        with self._trava:
            erro = ctypes.c_int(0)
            opcoes = self.lib.tox_options_new(ctypes.byref(erro))
            if not opcoes:
                raise RuntimeError("Falha ao criar Tox_Options")
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
            if not self.tox:
                raise RuntimeError(f"Falha ao criar instância Tox (código {erro_new.value})")

            self._registrar_callbacks()
            self._carregar_amigos_existentes()
            self._salvar_estado_sem_trava()
        self.log(f"[Tox] Identidade pronta. ID: {self.obter_endereco_hex()}")

    def _registrar_callbacks(self):
        c_void_p = ctypes.c_void_p
        CB_SELF_CONN = ctypes.CFUNCTYPE(None, c_void_p, ctypes.c_int, c_void_p)
        CB_FRIEND_REQ = ctypes.CFUNCTYPE(None, c_void_p, ctypes.POINTER(ctypes.c_uint8),
                                          ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, c_void_p)
        CB_FRIEND_CONN = ctypes.CFUNCTYPE(None, c_void_p, ctypes.c_uint32, ctypes.c_int, c_void_p)
        CB_FRIEND_PKT = ctypes.CFUNCTYPE(None, c_void_p, ctypes.c_uint32,
                                          ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t, c_void_p)

        def ao_mudar_conexao_propria(tox, status, user_data):
            nomes = {0: "Offline", 1: "Conectado (TCP)", 2: "Conectado (UDP)"}
            self.log(f"[Tox] Status da rede: {nomes.get(status, status)}")

        def ao_receber_pedido_amizade(tox, chave_ptr, msg_ptr, tamanho, user_data):
            chave_publica = bytes(ctypes.cast(
                chave_ptr, ctypes.POINTER(ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)).contents)
            chave_hex = chave_publica.hex()
            if self.auto_aceitar_amigos:
                erro = ctypes.c_int(0)
                buf = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE).from_buffer_copy(chave_publica)
                with self._trava:
                    numero = self.lib.tox_friend_add_norequest(self.tox, buf, ctypes.byref(erro))
                if erro.value == 0:
                    self._amigos[numero] = {"chave_publica": chave_hex, "status": 0}
                    self.log(f"[Tox] Pedido de amizade aceito: {chave_hex[:16]}...")
                    self._salvar_estado()
                else:
                    self.log(f"[Tox] Falha ao aceitar amizade (código {erro.value})")
            else:
                self.log(f"[Tox] Pedido de amizade ignorado (modo cliente): {chave_hex[:16]}...")

        def ao_mudar_conexao_amigo(tox, numero_amigo, status, user_data):
            info = self._amigos.setdefault(numero_amigo, {})
            info["status"] = status
            nomes = {0: "desconectado", 1: "conectado(TCP)", 2: "conectado(UDP)"}
            self.log(f"[Tox] Amigo {numero_amigo}: {nomes.get(status, status)}")

        def ao_receber_pacote(tox, numero_amigo, dados_ptr, tamanho, user_data):
            try:
                bruto = bytes(ctypes.cast(
                    dados_ptr, ctypes.POINTER(ctypes.c_uint8 * tamanho)).contents)
            except Exception:
                return
            self._processar_fragmento(numero_amigo, bruto)

        self._cb_self_conn = CB_SELF_CONN(ao_mudar_conexao_propria)
        self._cb_friend_req = CB_FRIEND_REQ(ao_receber_pedido_amizade)
        self._cb_friend_conn = CB_FRIEND_CONN(ao_mudar_conexao_amigo)
        self._cb_friend_pkt = CB_FRIEND_PKT(ao_receber_pacote)
        self._refs_callbacks += [self._cb_self_conn, self._cb_friend_req,
                                  self._cb_friend_conn, self._cb_friend_pkt]

        self.lib.tox_callback_self_connection_status(self.tox, self._cb_self_conn)
        self.lib.tox_callback_friend_request(self.tox, self._cb_friend_req)
        self.lib.tox_callback_friend_connection_status(self.tox, self._cb_friend_conn)
        self.lib.tox_callback_friend_lossless_packet(self.tox, self._cb_friend_pkt)

    def _carregar_amigos_existentes(self):
        tamanho = self.lib.tox_self_get_friend_list_size(self.tox)
        if tamanho == 0:
            return
        buf = (ctypes.c_uint32 * tamanho)()
        self.lib.tox_self_get_friend_list(self.tox, buf)
        for numero in buf:
            erro = ctypes.c_int(0)
            chave_buf = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)()
            ok = self.lib.tox_friend_get_public_key(self.tox, numero, chave_buf, ctypes.byref(erro))
            chave_hex = bytes(chave_buf).hex() if ok else ""
            self._amigos[numero] = {"chave_publica": chave_hex, "status": 0}

    def _processar_fragmento(self, numero_amigo, bruto: bytes):
        if len(bruto) < 9 or bruto[0] != PACOTE_ID_DADOS:
            return
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
                # Processa em thread separada para não travar o loop do Tox
                threading.Thread(target=self._callback_mensagem,
                                  args=(numero_amigo, mensagem), daemon=True).start()

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
                ok = self.lib.tox_friend_send_lossless_packet(
                    self.tox, numero_amigo, buf, len(dados_envio), ctypes.byref(erro))
            if not ok:
                raise RuntimeError(f"Falha ao enviar pacote Tox (código {erro.value})")

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
            try:
                self._salvar_estado()
            except Exception as e:
                self.log(f"[Tox] Erro salvando estado: {e}")

    def _loop_bootstrap_periodico(self):
        while self._rodando:
            try:
                self.bootstrap(obter_nos_bootstrap())
            except Exception as e:
                self.log(f"[Tox] Erro no bootstrap periódico: {e}")
            time.sleep(1800)

    def bootstrap(self, nos: list):
        for no in nos:
            try:
                chave = bytes.fromhex(no["chave_publica"])
                buf = (ctypes.c_uint8 * len(chave)).from_buffer_copy(chave)
                erro = ctypes.c_int(0)
                with self._trava:
                    ok = self.lib.tox_bootstrap(self.tox, no["ip"].encode(), int(no["porta"]),
                                                 buf, ctypes.byref(erro))
                if not ok:
                    self.log(f"[Tox] Bootstrap falhou: {no['ip']}:{no['porta']} (código {erro.value})")
            except Exception as e:
                self.log(f"[Tox] Erro bootstrap {no}: {e}")

    def _salvar_estado(self):
        with self._trava:
            self._salvar_estado_sem_trava()

    def _salvar_estado_sem_trava(self):
        tamanho = self.lib.tox_get_savedata_size(self.tox)
        buffer = (ctypes.c_uint8 * tamanho)()
        self.lib.tox_get_savedata(self.tox, buffer)
        dados = bytes(buffer)
        tmp = self.caminho_savedata.with_suffix(".tmp")
        tmp.write_bytes(dados)
        tmp.replace(self.caminho_savedata)

    def obter_endereco_bytes(self) -> bytes:
        buf = (ctypes.c_uint8 * TOX_ADDRESS_SIZE)()
        with self._trava:
            self.lib.tox_self_get_address(self.tox, buf)
        return bytes(buf)

    def obter_endereco_hex(self) -> str:
        return self.obter_endereco_bytes().hex().upper()

    def status_rede(self) -> int:
        with self._trava:
            return self.lib.tox_self_get_connection_status(self.tox)

    def renovar_nospam(self):
        novo = struct.unpack(">I", secrets.token_bytes(4))[0]
        with self._trava:
            self.lib.tox_self_set_nospam(self.tox, novo)
        self._salvar_estado()
        return self.obter_endereco_hex()

    def listar_amigos(self):
        return [{"numero": n, "chave_publica": i.get("chave_publica", ""),
                 "conectado": i.get("status", 0) != 0} for n, i in self._amigos.items()]

    def remover_amigo(self, numero_amigo):
        erro = ctypes.c_int(0)
        with self._trava:
            self.lib.tox_friend_delete(self.tox, numero_amigo, ctypes.byref(erro))
        self._amigos.pop(numero_amigo, None)
        self._salvar_estado()

    def parar(self):
        self._rodando = False
        try:
            self._salvar_estado()
        except Exception:
            pass
        with self._trava:
            if self.tox:
                self.lib.tox_kill(self.tox)
                self.tox = None

    def reiniciar_identidade(self):
        self.parar()
        if self.caminho_savedata.exists():
            self.caminho_savedata.unlink()
        self._amigos.clear()
        self._criar_tox()
        self.iniciar_loop()


# =====================================================================
# DISPATCHER DE MENSAGENS (lógica de negócio)
# =====================================================================
SESSOES_SSH = {}  # (numero_amigo, session_id) -> canal paramiko

def lidar_mensagem_recebida(numero_amigo, mensagem):
    tipo = mensagem.get("tipo")
    try:
        if tipo == "listar_servicos":
            servicos = [{"id": s["id"], "nome": s["nome"], "tipo": s["tipo"],
                         "comentario": s.get("comentario", "")}
                        for s in obter_servicos() if s.get("ativo")]
            no_tox.enviar_mensagem(numero_amigo, {"tipo": "lista_servicos", "dados": servicos})
        elif tipo == "http_request":
            lidar_http(numero_amigo, mensagem)
        elif tipo == "ssh_abrir":
            lidar_ssh_abrir(numero_amigo, mensagem)
        elif tipo == "ssh_dados":
            lidar_ssh_dados(numero_amigo, mensagem)
        elif tipo == "ssh_fechar":
            chave = (numero_amigo, mensagem.get("session_id"))
            canal = SESSOES_SSH.pop(chave, None)
            if canal:
                try: canal.close()
                except Exception: pass
    except Exception as e:
        log(f"Erro processando mensagem '{tipo}': {e}")

def lidar_http(numero_amigo, msg):
    import base64
    req_id = msg.get("id")
    servico_id = msg.get("service_id")
    servico = next((s for s in obter_servicos() if s["id"] == servico_id and s.get("ativo")), None)
    if not servico:
        no_tox.enviar_mensagem(numero_amigo, {"tipo": "http_response", "id": req_id, "status": 404,
                                               "headers": {}, "body": base64.b64encode(b"Servico indisponivel").decode()})
        return
    url = f"http://{servico['host']}:{servico['porta']}{msg.get('path','/')}"
    metodo = msg.get("method", "GET")
    corpo = base64.b64decode(msg.get("body", "")) if msg.get("body") else None
    cabecalhos = msg.get("headers", {}) or {}
    try:
        req = urllib.request.Request(url, data=corpo, method=metodo, headers=cabecalhos)
        with urllib.request.urlopen(req, timeout=15) as resp:
            corpo_resp = resp.read(); status = resp.status; cab_resp = dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        corpo_resp = e.read(); status = e.code
        cab_resp = dict(e.headers.items()) if e.headers else {}
    except Exception as e:
        corpo_resp = f"Erro ao acessar servico local: {e}".encode(); status = 502; cab_resp = {}
    no_tox.enviar_mensagem(numero_amigo, {"tipo": "http_response", "id": req_id, "status": status,
                                           "headers": cab_resp, "body": base64.b64encode(corpo_resp).decode()})

def lidar_ssh_abrir(numero_amigo, msg):
    import base64
    sid = msg.get("session_id")
    chave_sessao = (numero_amigo, sid)
    if not PARAMIKO_OK:
        no_tox.enviar_mensagem(numero_amigo, {"tipo": "ssh_erro", "session_id": sid,
                                               "mensagem": "paramiko nao instalado no servidor"})
        return
    ssh_servico = next((s for s in obter_servicos() if s["tipo"] == "ssh" and s.get("ativo")), None)
    if not ssh_servico:
        no_tox.enviar_mensagem(numero_amigo, {"tipo": "ssh_erro", "session_id": sid,
                                               "mensagem": "SSH desativado no servidor"})
        return
    usuario = msg.get("usuario"); senha = msg.get("senha")
    try:
        cliente = paramiko.SSHClient()
        cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cliente.connect(ssh_servico["host"], port=ssh_servico["porta"],
                         username=usuario, password=senha, timeout=10)
        canal = cliente.invoke_shell(term="xterm")
        canal.settimeout(0.0)
        SESSOES_SSH[chave_sessao] = canal
        no_tox.enviar_mensagem(numero_amigo, {"tipo": "ssh_aberto", "session_id": sid})

        def ler_canal():
            while True:
                try:
                    if canal.recv_ready():
                        dados = canal.recv(2048)
                        if not dados: break
                        no_tox.enviar_mensagem(numero_amigo, {"tipo": "ssh_dados", "session_id": sid,
                                                               "dados": base64.b64encode(dados).decode()})
                    else:
                        time.sleep(0.03)
                    if canal.closed: break
                except Exception:
                    break
            no_tox.enviar_mensagem(numero_amigo, {"tipo": "ssh_fechado", "session_id": sid})
            SESSOES_SSH.pop(chave_sessao, None)

        threading.Thread(target=ler_canal, daemon=True).start()
    except Exception as e:
        no_tox.enviar_mensagem(numero_amigo, {"tipo": "ssh_erro", "session_id": sid, "mensagem": str(e)})

def lidar_ssh_dados(numero_amigo, msg):
    import base64
    sid = msg.get("session_id")
    canal = SESSOES_SSH.get((numero_amigo, sid))
    if canal:
        try: canal.send(base64.b64decode(msg.get("dados", "")))
        except Exception: pass

# =====================================================================
# INICIALIZAÇÃO DA IDENTIDADE TOX
# =====================================================================
no_tox = NoTox(ARQ_SAVEDATA, auto_aceitar_amigos=True, log_fn=log)
no_tox.definir_callback_mensagem(lidar_mensagem_recebida)
no_tox.bootstrap(obter_nos_bootstrap())
no_tox.iniciar_loop()

# =====================================================================
# FLASK (PAINEL WEB - PORTA 2000)
# =====================================================================
app = Flask(__name__, template_folder=str(BASE_DIR / "templates"))

@app.route("/")
def index():
    return render_template("index.html",
        endereco_tox=no_tox.obter_endereco_hex(),
        status_rede=no_tox.status_rede(),
        amigos=no_tox.listar_amigos(),
        servicos=obter_servicos(),
        nos_bootstrap=obter_nos_bootstrap(),
        paramiko_ok=PARAMIKO_OK)

@app.route("/api/status")
def api_status():
    return jsonify({"status_rede": no_tox.status_rede(), "amigos": no_tox.listar_amigos()})

@app.route("/api/chave/renovar", methods=["POST"])
def api_renovar_chave():
    novo_endereco = no_tox.renovar_nospam()
    return jsonify({"endereco": novo_endereco})

@app.route("/api/chave/excluir", methods=["POST"])
def api_excluir_chave():
    no_tox.reiniciar_identidade()
    log("Identidade Tox reiniciada pelo administrador.")
    return jsonify({"endereco": no_tox.obter_endereco_hex()})

@app.route("/api/amigos/<int:numero>/remover", methods=["POST"])
def api_remover_amigo(numero):
    no_tox.remover_amigo(numero)
    return jsonify({"ok": True})

@app.route("/api/bootstrap/atualizar", methods=["POST"])
def api_atualizar_bootstrap():
    ok, qtd = atualizar_nos_bootstrap_online()
    return jsonify({"ok": ok, "novos": qtd, "nos": obter_nos_bootstrap()})

@app.route("/api/bootstrap/adicionar", methods=["POST"])
def api_adicionar_bootstrap():
    dados = request.get_json(force=True)
    nos = obter_nos_bootstrap()
    nos.append({"ip": dados["ip"], "porta": int(dados["porta"]),
                "chave_publica": dados["chave_publica"].upper(), "origem": "manual"})
    salvar_nos_bootstrap(nos)
    no_tox.bootstrap([nos[-1]])
    return jsonify({"ok": True})

@app.route("/api/bootstrap/remover/<int:indice>", methods=["POST"])
def api_remover_bootstrap(indice):
    nos = obter_nos_bootstrap()
    if 0 <= indice < len(nos):
        nos.pop(indice)
        salvar_nos_bootstrap(nos)
    return jsonify({"ok": True})

@app.route("/api/servicos", methods=["POST"])
def api_adicionar_servico():
    dados = request.get_json(force=True)
    servicos = obter_servicos()
    novo = {"id": str(uuid.uuid4())[:8], "nome": dados.get("nome", "Servico"), "tipo": "http",
            "host": dados.get("host", "127.0.0.1"), "porta": int(dados.get("porta", 80)),
            "comentario": dados.get("comentario", ""), "ativo": False, "builtin": False}
    servicos.append(novo)
    salvar_servicos(servicos)
    log(f"Servico adicionado: {novo['nome']} ({novo['host']}:{novo['porta']})")
    return jsonify(novo)

@app.route("/api/servicos/<sid>", methods=["PUT"])
def api_editar_servico(sid):
    dados = request.get_json(force=True)
    servicos = obter_servicos()
    for s in servicos:
        if s["id"] == sid:
            if not s.get("builtin"):
                s["nome"] = dados.get("nome", s["nome"])
                s["host"] = dados.get("host", s["host"])
                s["porta"] = int(dados.get("porta", s["porta"]))
            s["comentario"] = dados.get("comentario", s.get("comentario", ""))
            salvar_servicos(servicos)
            return jsonify(s)
    return jsonify({"erro": "nao encontrado"}), 404

@app.route("/api/servicos/<sid>", methods=["DELETE"])
def api_remover_servico(sid):
    servicos = obter_servicos()
    alvo = next((s for s in servicos if s["id"] == sid), None)
    if alvo and alvo.get("builtin"):
        return jsonify({"erro": "servico padrao nao pode ser removido"}), 400
    servicos = [s for s in servicos if s["id"] != sid]
    salvar_servicos(servicos)
    return jsonify({"ok": True})

@app.route("/api/servicos/<sid>/alternar", methods=["POST"])
def api_alternar_servico(sid):
    servicos = obter_servicos()
    for s in servicos:
        if s["id"] == sid:
            s["ativo"] = not s.get("ativo", False)
            salvar_servicos(servicos)
            log(f"Servico '{s['nome']}' {'ativado' if s['ativo'] else 'desativado'}")
            return jsonify(s)
    return jsonify({"erro": "nao encontrado"}), 404

def main():
    log("Servidor de acesso remoto via Tox iniciado.")
    app.run(host="127.0.0.1", port=2000, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
