#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tox_remoto.py - RRFS Servidores v3.0
Acesso remoto via protocolo Tox (libtoxcore real via ctypes).

v3.0 (correções do proxy HTTP):
  - CORRIGIDO (causa dos arquivos corrompidos): requisições sem corpo
    (GET) eram processadas DUAS vezes - uma em _http_abrir e outra ao
    chegar 'http_corpo_fim' do cliente. As duas threads jogavam blocos
    na mesma fila do cliente (dados duplicados/embaralhados) e geravam
    pares de "Connection refused" no log. Agora cada requisição é
    iniciada uma única vez ('iniciado'), e o cliente não envia mais
    corpo_fim quando não há corpo.
  - 'http_cancelar' antes do início limpa a requisição (upload
    interrompido não é mais processado como se estivesse completo).
  - read() -> read1(): não espera encher o bloco (streams sem tamanho,
    MJPEG, long-polling não "congelam" mais).
  - Content-Length da resposta é preservado e CONFERIDO: se o serviço
    local fechar antes do fim, a transferência é abortada com erro
    (nunca mais "fim" falso).
  - Fragmentos parciais só expiram após TIMEOUT_FRAGMENTOS sem NENHUM
    progresso (antes: 90s fixos desde o 1º fragmento -> buraco no
    arquivo em túnel lento).
  - Origin/Referer reescritos para o backend; Location convertido em
    caminho relativo; Set-Cookie sem Domain/Secure/SameSite=None.
  - Accept-Encoding não é mais duplicado.
  - Conexão ao backend: tenta o host cadastrado, 127.0.0.1 e IPs locais
    (se o serviço é desta máquina), lembrando o que funcionou.
  - UFW: destino que não é 127.x recebe regra de SAÍDA em qualquer
    interface (antes ia para 'lo' e o tráfego a containers era barrado).
  - Novo: testar_servico() para diagnóstico.

Histórico anterior: v2.9 (envio sem desistência por tempo fixo),
v2.8 (normalização de caminho), v2.7 (semáforo/retry), v2.6 (streaming).
"""

import os
import re
import ssl
import json
import math
import time
import uuid
import base64
import struct
import socket
import secrets
import tempfile
import ipaddress
import logging
import threading
import queue
import http.client
import urllib.request
from urllib.parse import quote, urlsplit
import ctypes
import ctypes.util
from datetime import datetime

from modulos.utils import executar_comando

try:
    import paramiko
    PARAMIKO_OK = True
except ImportError:
    PARAMIKO_OK = False

logger = logging.getLogger('RRFS.Tox')

# ── constantes do protocolo ────────────────────────────────
TOX_ADDRESS_SIZE        = 38
TOX_PUBLIC_KEY_SIZE     = 32
TOX_SAVEDATA_TYPE_NONE  = 0
TOX_SAVEDATA_TYPE_SAVE  = 1
PACOTE_ID_DADOS         = 160      # faixa lossless customizada 160-191
MAX_FRAGMENTO           = 1200     # < 1373 (limite do Tox)
MAX_FRAGMENTOS_MSG      = 4000
ERRO_SENDQ              = 7        # TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ
TIMEOUT_FRAGMENTOS      = 600      # s SEM progresso p/ descartar parcial

ESPERA_MIN_FILA_CHEIA = 0.05
ESPERA_MAX_FILA_CHEIA = 0.5

# ── streaming HTTP ──────────────────────────────────────────
TAM_BLOCO_STREAM          = 128 * 1024
TIMEOUT_CONECTAR_BACKEND  = 15
TIMEOUT_ESPERAR_CABECALHOS = 120
TIMEOUT_LEITURA_SEM_DADOS  = 90
TAM_MAX_CORPO_DISCO        = 10 * 1024 ** 3
MAX_REQS_SIMULTANEAS_POR_AMIGO = 40

MAX_CONEXOES_SIMULTANEAS_POR_SERVICO = 8
TIMEOUT_ESPERAR_VAGA_CONEXAO         = 40
RETRY_CONEXAO_RECUSADA               = 6
RETRY_CONEXAO_ESPERAS                = (0.1, 0.2, 0.4, 0.8, 1.5, 2.5)

PORTA_UDP_INICIO = 33445
PORTA_UDP_FIM    = 33545

RE_IFACE = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
RE_NOME  = re.compile(r'^[\w .\-]{1,60}$', re.UNICODE)
RE_HEX64 = re.compile(r'^[0-9A-Fa-f]{64}$')
RE_ADDR  = re.compile(r'^[0-9A-Fa-f]{76}$')

_SAFE_CAMINHO = "/%:@!$&'()*+,;="
_SAFE_QUERY   = "%:@!$&'()*+,;=/?~"

_LIB = None
_cache_ips = {'ts': 0, 'ips': {'127.0.0.1'}}


# ══════════════════════════════════════════════════════════
# HELPERS DO PROXY
# ══════════════════════════════════════════════════════════

def _normalizar_caminho_http(caminho):
    """Percent-encoding correto do caminho (sem dupla codificação)."""
    if not caminho:
        return '/'
    partes = caminho.split('?', 1)
    seguro = quote(partes[0], safe=_SAFE_CAMINHO)
    if not seguro.startswith('/'):
        seguro = '/' + seguro
    if len(partes) == 2:
        seguro += '?' + quote(partes[1], safe=_SAFE_QUERY)
    return seguro


def _sanitizar_valor_cabecalho(valor):
    return str(valor).replace('\r', '').replace('\n', '')


def _ips_locais():
    """IPv4 desta máquina (cache de 60s)."""
    if time.time() - _cache_ips['ts'] < 60:
        return _cache_ips['ips']
    ips = {'127.0.0.1'}
    try:
        r = executar_comando(
            "ip -4 -o addr show 2>/dev/null | awk '{print $4}' | "
            "cut -d/ -f1", timeout=5
        )
        if r['sucesso']:
            for l in r['saida'].splitlines():
                l = l.strip()
                if l:
                    ips.add(l)
    except Exception as e:
        logger.error(f"_ips_locais: {e}")
    _cache_ips['ts'] = time.time()
    _cache_ips['ips'] = ips
    return ips


def _reescrever_location(valor, hosts_backend):
    """Redirect absoluto para o backend vira caminho relativo (assim
    continua passando pelo proxy)."""
    try:
        p = urlsplit(valor)
        if (p.scheme in ('http', 'https') and p.hostname and
                p.hostname.lower() in hosts_backend):
            rel = p.path or '/'
            if p.query:
                rel += '?' + p.query
            if p.fragment:
                rel += '#' + p.fragment
            return rel
    except Exception:
        pass
    return valor


def _ajustar_set_cookie(valor):
    """O navegador acessa por http://s-<id>.localhost: Domain do
    backend, Secure e SameSite=None fariam o cookie ser rejeitado."""
    v = re.sub(r';\s*Domain=[^;]*', '', valor, flags=re.I)
    v = re.sub(r';\s*Secure\s*(?=;|$)', '', v, flags=re.I)
    v = re.sub(r'(;\s*SameSite=)None', r'\1Lax', v, flags=re.I)
    return v


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
    raise RuntimeError(
        f"libtoxcore não encontrada/compatível: {erro_final}"
    )


def _configurar_assinaturas(lib):
    vp   = ctypes.c_void_p
    ci   = ctypes.c_int
    u8p  = ctypes.POINTER(ctypes.c_uint8)
    u32  = ctypes.c_uint32
    u16  = ctypes.c_uint16
    st   = ctypes.c_size_t
    cb   = ctypes.c_bool
    cp   = ctypes.c_char_p
    eri  = ctypes.POINTER(ci)

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
    fn('tox_self_set_nospam', None, [vp, u32])
    fn('tox_self_get_connection_status', ci, [vp])
    fn('tox_get_savedata_size', st, [vp])
    fn('tox_get_savedata', None, [vp, u8p])
    fn('tox_friend_add', u32, [vp, u8p, u8p, st, eri])
    fn('tox_friend_add_norequest', u32, [vp, u8p, eri])
    fn('tox_friend_delete', cb, [vp, u32, eri])
    fn('tox_friend_get_public_key', cb, [vp, u32, u8p, eri])
    fn('tox_friend_send_lossless_packet', cb, [vp, u32, u8p, st, eri])
    fn('tox_self_get_friend_list_size', st, [vp])
    fn('tox_self_get_friend_list', None, [vp, ctypes.POINTER(u32)])
    fn('tox_callback_self_connection_status', None, [vp, vp])
    fn('tox_callback_friend_request', None, [vp, vp])
    fn('tox_callback_friend_connection_status', None, [vp, vp])
    fn('tox_callback_friend_lossless_packet', None, [vp, vp])


# ══════════════════════════════════════════════════════════
# NÓ TOX (baixo nível)
# ══════════════════════════════════════════════════════════

class _NoTox:
    """Identidade Tox. A libtoxcore NÃO é thread-safe: toda chamada
    passa pela mesma RLock. Despacho de mensagens é SEQUENCIAL."""

    def __init__(self, caminho_savedata, cb_pedido, cb_mensagem,
                 cb_amigo, log_fn):
        self.lib       = carregar_libtoxcore()
        self.caminho   = caminho_savedata
        self.cb_pedido = cb_pedido
        self.cb_msg    = cb_mensagem
        self.cb_amigo  = cb_amigo
        self.log       = log_fn
        self.tox       = None
        self._rodando  = False
        self._trava    = threading.RLock()
        self._amigos   = {}
        self._frag     = {}
        self._refs     = []
        self._fila_msgs = queue.Queue()
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
                    self.lib.tox_options_set_savedata_type(
                        op, TOX_SAVEDATA_TYPE_SAVE
                    )
                    buf_save = (ctypes.c_uint8 * len(dados)
                                ).from_buffer_copy(dados)
                    self.lib.tox_options_set_savedata_data(
                        op, buf_save, len(dados)
                    )
            if buf_save is None:
                self.lib.tox_options_set_savedata_type(
                    op, TOX_SAVEDATA_TYPE_NONE
                )

            e2 = ctypes.c_int(0)
            self.tox = self.lib.tox_new(op, ctypes.byref(e2))
            self.lib.tox_options_free(op)
            if not self.tox:
                raise RuntimeError(
                    f"Falha ao criar instância Tox (código {e2.value})"
                )
            self._registrar_callbacks()
            self._carregar_amigos()
            self._salvar_sem_trava()
        self.log(f"Identidade pronta: {self.endereco_hex()[:16]}...")

    def _registrar_callbacks(self):
        vp  = ctypes.c_void_p
        u8p = ctypes.POINTER(ctypes.c_uint8)
        CB_SELF = ctypes.CFUNCTYPE(None, vp, ctypes.c_int, vp)
        CB_REQ  = ctypes.CFUNCTYPE(None, vp, u8p, u8p,
                                   ctypes.c_size_t, vp)
        CB_CONN = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32,
                                   ctypes.c_int, vp)
        CB_PKT  = ctypes.CFUNCTYPE(None, vp, ctypes.c_uint32, u8p,
                                   ctypes.c_size_t, vp)

        def ao_rede(tox, status, ud):
            nomes = {0: 'Offline', 1: 'Conectado (TCP)',
                     2: 'Conectado (UDP)'}
            self.log(f"Rede Tox: {nomes.get(status, status)}")

        def ao_pedido(tox, chave_ptr, msg_ptr, tam, ud):
            try:
                chave = bytes(ctypes.cast(
                    chave_ptr,
                    ctypes.POINTER(ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE)
                ).contents)
                texto = ''
                if tam and msg_ptr:
                    n = min(int(tam), 200)
                    texto = bytes(ctypes.cast(
                        msg_ptr, ctypes.POINTER(ctypes.c_uint8 * n)
                    ).contents).decode('utf-8', errors='replace')
                self.cb_pedido(chave, texto)
            except Exception as e:
                logger.error(f"tox ao_pedido: {e}")

        def ao_amigo(tox, numero, status, ud):
            self._amigos.setdefault(numero, {})['status'] = status
            try:
                self.cb_amigo(numero, status)
            except Exception as e:
                logger.error(f"tox ao_amigo: {e}")

        def ao_pacote(tox, numero, dados_ptr, tam, ud):
            try:
                bruto = bytes(ctypes.cast(
                    dados_ptr, ctypes.POINTER(ctypes.c_uint8 * tam)
                ).contents)
            except Exception:
                return
            self._fragmento(numero, bruto)

        self._c1 = CB_SELF(ao_rede)
        self._c2 = CB_REQ(ao_pedido)
        self._c3 = CB_CONN(ao_amigo)
        self._c4 = CB_PKT(ao_pacote)
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
            ok = self.lib.tox_friend_get_public_key(
                self.tox, numero, kb, ctypes.byref(e)
            )
            self._amigos[numero] = {
                'chave_publica': bytes(kb).hex().upper() if ok else '',
                'status': 0
            }

    # ── fragmentação ────────────────────────────────────────

    def _fragmento(self, numero, bruto):
        if len(bruto) < 9 or bruto[0] != PACOTE_ID_DADOS:
            return
        frame_id = bruto[1:5]
        idx   = struct.unpack('>H', bruto[5:7])[0]
        total = struct.unpack('>H', bruto[7:9])[0]
        if total < 1 or total > MAX_FRAGMENTOS_MSG or idx >= total:
            return
        k = (numero, frame_id)
        reg = self._frag.setdefault(
            k, {'t': time.time(), 'total': total, 'partes': {}}
        )
        if reg['total'] != total:
            self._frag.pop(k, None)
            return
        reg['t'] = time.time()      # v3.0: renova a cada fragmento
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
        for k in [k for k, v in self._frag.items()
                  if agora - v['t'] > TIMEOUT_FRAGMENTOS]:
            self._frag.pop(k, None)

    def enviar(self, numero, mensagem, cancelado=None):
        """Fragmenta e envia via pacotes lossless (confiável e
        ordenado). Fila cheia = espera (backpressure). Só levanta
        exceção se o amigo desconectar ou 'cancelado' for sinalizado;
        o chamador DEVE abortar a operação nesse caso."""
        if self._amigos.get(numero, {}).get('status', 0) == 0:
            raise RuntimeError('Amigo desconectado')
        bruto = json.dumps(mensagem).encode('utf-8')
        fid   = secrets.token_bytes(4)
        total = max(1, math.ceil(len(bruto) / MAX_FRAGMENTO))
        if total > MAX_FRAGMENTOS_MSG:
            raise RuntimeError('Mensagem grande demais (ajuste '
                              'TAM_BLOCO_STREAM)')
        for idx in range(total):
            pedaco = bruto[idx * MAX_FRAGMENTO:(idx + 1) * MAX_FRAGMENTO]
            pkt = (bytes([PACOTE_ID_DADOS]) + fid +
                   struct.pack('>H', idx) + struct.pack('>H', total) +
                   pedaco)
            buf = (ctypes.c_uint8 * len(pkt)).from_buffer_copy(pkt)
            tentativas = 0
            while True:
                if cancelado is not None and cancelado.is_set():
                    raise RuntimeError('Cancelado pelo cliente')
                erro = ctypes.c_int(0)
                with self._trava:
                    if not self.tox:
                        raise RuntimeError('Tox parado')
                    ok = self.lib.tox_friend_send_lossless_packet(
                        self.tox, numero, buf, len(pkt),
                        ctypes.byref(erro)
                    )
                if ok:
                    break
                if erro.value == ERRO_SENDQ:
                    if self._amigos.get(numero, {}).get(
                            'status', 0) == 0:
                        raise RuntimeError(
                            'Amigo desconectou durante o envio'
                        )
                    tentativas += 1
                    time.sleep(min(
                        ESPERA_MIN_FILA_CHEIA * (1 + tentativas // 10),
                        ESPERA_MAX_FILA_CHEIA
                    ))
                    continue
                raise RuntimeError(
                    f'Falha ao enviar pacote Tox (código {erro.value})'
                )

    # ── loops ─────────────────────────────────────────────

    def iniciar_loop(self):
        self._rodando = True
        threading.Thread(target=self._loop, daemon=True,
                         name='Tox-Loop').start()
        threading.Thread(target=self._loop_salvar, daemon=True,
                         name='Tox-Save').start()
        threading.Thread(target=self._loop_mensagens, daemon=True,
                         name='Tox-Dispatch').start()

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

    def _loop_mensagens(self):
        while self._rodando:
            try:
                numero, msg = self._fila_msgs.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self.cb_msg(numero, msg)
            except Exception as e:
                logger.error(f"tox despacho mensagem: {e}")

    def _loop_salvar(self):
        while self._rodando:
            for _ in range(20):
                if not self._rodando:
                    return
                time.sleep(1)
            try:
                self.salvar()
            except Exception as e:
                logger.error(f"tox salvar periódico: {e}")

    # ── bootstrap ─────────────────────────────────────────

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
                    if self.lib.tox_bootstrap(
                            self.tox, host, int(no['porta']),
                            buf, ctypes.byref(e)):
                        ok_total += 1
                    tcp = int((no.get('tcp_ports') or [no['porta']])[0])
                    e2 = ctypes.c_int(0)
                    self.lib.tox_add_tcp_relay(
                        self.tox, host, tcp, buf, ctypes.byref(e2)
                    )
            except Exception as e:
                logger.error(f"tox bootstrap {no.get('ip')}: {e}")
        return ok_total

    # ── persistência ──────────────────────────────────────

    def salvar(self):
        with self._trava:
            self._salvar_sem_trava()

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

    # ── consultas / ações ─────────────────────────────────

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

    def renovar_nospam(self):
        novo = struct.unpack('>I', secrets.token_bytes(4))[0]
        with self._trava:
            self.lib.tox_self_set_nospam(self.tox, novo)
        self.salvar()
        return self.endereco_hex()

    def aceitar_chave(self, chave_bytes):
        buf = (ctypes.c_uint8 * TOX_PUBLIC_KEY_SIZE
               ).from_buffer_copy(chave_bytes)
        erro = ctypes.c_int(0)
        with self._trava:
            numero = self.lib.tox_friend_add_norequest(
                self.tox, buf, ctypes.byref(erro)
            )
        if erro.value != 0:
            return None, erro.value
        self._amigos[numero] = {
            'chave_publica': chave_bytes.hex().upper(), 'status': 0
        }
        self.salvar()
        return numero, 0

    def adicionar_por_endereco(self, endereco_bytes, mensagem):
        ab = (ctypes.c_uint8 * TOX_ADDRESS_SIZE
              ).from_buffer_copy(endereco_bytes)
        m  = mensagem.encode('utf-8')[:200] or b'RRFS'
        mb = (ctypes.c_uint8 * len(m)).from_buffer_copy(m)
        erro = ctypes.c_int(0)
        with self._trava:
            numero = self.lib.tox_friend_add(
                self.tox, ab, mb, len(m), ctypes.byref(erro)
            )
        if erro.value != 0:
            return None, erro.value
        self._amigos[numero] = {
            'chave_publica': endereco_bytes[:32].hex().upper(),
            'status': 0
        }
        self.salvar()
        return numero, 0

    def listar_amigos(self):
        return [{
            'numero': n,
            'chave_publica': i.get('chave_publica', ''),
            'conectado': i.get('status', 0) != 0
        } for n, i in sorted(self._amigos.items())]

    def remover_amigo(self, numero):
        erro = ctypes.c_int(0)
        with self._trava:
            if self.tox:
                self.lib.tox_friend_delete(
                    self.tox, numero, ctypes.byref(erro)
                )
        self._amigos.pop(numero, None)
        self.salvar()

    def parar(self):
        self._rodando = False
        with self._trava:
            if self.tox:
                try:
                    self._salvar_sem_trava()
                except Exception as e:
                    logger.error(f"tox parar/salvar: {e}")
                self.lib.tox_kill(self.tox)
                self.tox = None


# ══════════════════════════════════════════════════════════
# GERENCIADOR (integração com o painel RRFS)
# ══════════════════════════════════════════════════════════

class ToxManager:

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.dir      = os.path.join(base_dir, 'dados', 'tox')
        self.cfg_path = os.path.join(self.dir, 'config.json')
        self.nos_path = os.path.join(self.dir, 'nos_bootstrap.json')
        self.save_path = os.path.join(self.dir, 'identidade.tox')
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        os.makedirs(self._tmp_dir(), mode=0o700, exist_ok=True)

        self._fw       = None
        self._no       = None
        self._lock     = threading.RLock()
        self._ssh      = {}
        self._reqs     = {}
        self._sem_servicos = {}
        self._sem_lock      = threading.Lock()
        self._host_efetivo  = {}   # sid -> host que funcionou
        self.config    = self._carregar()

    def set_firewall(self, fw):
        self._fw = fw

    def _tmp_dir(self):
        return os.path.join(self.dir, 'tmp')

    def _semaforo_servico(self, sid):
        with self._sem_lock:
            sem = self._sem_servicos.get(sid)
            if sem is None:
                sem = threading.Semaphore(
                    MAX_CONEXOES_SIMULTANEAS_POR_SERVICO
                )
                self._sem_servicos[sid] = sem
            return sem

    # ── config ────────────────────────────────────────────

    def _padrao(self):
        return {
            'ativo': False,
            'aceitar_automatico': False,
            'pendentes': [],
            'servicos': [
                {'id': 'builtin-ssh', 'nome': 'SSH', 'tipo': 'ssh',
                 'esquema': 'http', 'interface': 'localhost',
                 'host': '127.0.0.1', 'porta': 22,
                 'comentario': 'Terminal SSH do servidor',
                 'ativo': False, 'builtin': True},
                {'id': 'builtin-admin', 'nome': 'Painel Admin',
                 'tipo': 'http', 'esquema': 'https',
                 'interface': 'localhost', 'host': '127.0.0.1',
                 'porta': 2000,
                 'comentario': 'Este painel (exige senha root)',
                 'ativo': False, 'builtin': True},
            ]
        }

    def _carregar(self):
        try:
            if os.path.exists(self.cfg_path):
                with open(self.cfg_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"tox carregar: {e}")
        return self._padrao()

    def _salvar(self):
        try:
            tmp = self.cfg_path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.cfg_path)
        except Exception as e:
            logger.error(f"tox salvar: {e}")

    def _log(self, msg):
        eventos = self.__dict__.setdefault('_eventos', [])
        eventos.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        del eventos[:-40]

    # ── dependências ──────────────────────────────────────

    def _lib_ok(self):
        try:
            carregar_libtoxcore()
            return True
        except Exception:
            return False

    def instalar_dependencias(self):
        try:
            executar_comando(
                'apt-get install -y libtoxcore-dev python3-paramiko',
                timeout=300
            )
            if self._lib_ok():
                return {'sucesso': True,
                        'mensagem': 'libtoxcore disponível.'}
            return {
                'sucesso': False,
                'erro': ('libtoxcore não encontrada após apt. '
                         'Compile o c-toxcore e rode '
                         '"ldconfig" (veja instruções).')
            }
        except Exception as e:
            logger.error(f"tox instalar_dependencias: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ── rede de saída ─────────────────────────────────────

    def _iface_saida(self):
        try:
            r = executar_comando(
                "ip route show default 2>/dev/null | "
                "awk '/default/ {print $5}' | head -1", timeout=10
            )
            if r['sucesso'] and r['saida'].strip():
                return r['saida'].strip()
        except Exception as e:
            logger.error(f"tox _iface_saida: {e}")
        return ''

    def _ip_interface(self, interface):
        if not interface or interface == 'localhost':
            return '127.0.0.1'
        if not RE_IFACE.match(interface):
            return '127.0.0.1'
        r = executar_comando(
            f"ip -4 addr show {interface} 2>/dev/null | "
            f"grep 'inet ' | awk '{{print $2}}' | "
            f"cut -d/ -f1 | head -1", timeout=10
        )
        return (r['saida'].strip() if r['sucesso'] else '') or '127.0.0.1'

    # ══════════════════════════════════════════════════════
    # STATUS
    # ══════════════════════════════════════════════════════

    def obter_status(self):
        try:
            rodando = self._no is not None
            rede = self._no.status_rede() if rodando else 0
            prob = []
            if self._fw:
                prob = self._fw.diagnosticar_regras_tox()
            return {
                'lib_ok':        self._lib_ok(),
                'paramiko_ok':   PARAMIKO_OK,
                'ativo':         self.config.get('ativo', False),
                'rodando':       rodando,
                'rede_status':   rede,
                'rede_texto':    {0: 'Offline', 1: 'Conectado (TCP)',
                                  2: 'Conectado (UDP)'}.get(rede, '?'),
                'endereco':      self._no.endereco_hex() if rodando
                                 else '',
                'aceitar_automatico': self.config.get(
                    'aceitar_automatico', False
                ),
                'amigos':        self._no.listar_amigos() if rodando
                                 else [],
                'pendentes':     self.config.get('pendentes', []),
                'servicos':      self.config.get('servicos', []),
                'total_servicos': len(self.config.get('servicos', [])),
                'nos_bootstrap': len(self._carregar_nos()),
                'interface_saida': self._iface_saida(),
                'fw_ok':         len(prob) == 0,
                'fw_problemas':  prob,
                'eventos':       list(self.__dict__.get('_eventos', [])),
                'transferencias_ativas': len(self._reqs),
            }
        except Exception as e:
            logger.error(f"tox obter_status: {e}")
            return {'lib_ok': False, 'ativo': False, 'rodando': False,
                    'servicos': [], 'amigos': [], 'pendentes': []}

    def obter_status_resumido(self):
        try:
            rodando = self._no is not None
            return {
                'ativo':    self.config.get('ativo', False),
                'rodando':  rodando,
                'rede_status': self._no.status_rede() if rodando else 0,
                'amigos':   len(self._no.listar_amigos()) if rodando
                            else 0,
                'servicos_ativos': len([
                    s for s in self.config.get('servicos', [])
                    if s.get('ativo')
                ]),
            }
        except Exception as e:
            logger.error(f"tox resumido: {e}")
            return {'ativo': False, 'rodando': False}

    # ══════════════════════════════════════════════════════
    # ATIVAR / DESATIVAR
    # ══════════════════════════════════════════════════════

    def _iniciar_no(self):
        with self._lock:
            if self._no is not None:
                return
            self._no = _NoTox(
                self.save_path, self._ao_pedido, self._ao_mensagem,
                self._ao_amigo, self._log
            )
            self._no.iniciar_loop()
        threading.Thread(target=self._bootstrap_inicial, daemon=True,
                         name='Tox-Bootstrap').start()
        threading.Thread(target=self._bootstrap_periodico, daemon=True,
                         name='Tox-BootstrapLoop').start()
        threading.Thread(target=self._loop_limpeza_tmp, daemon=True,
                         name='Tox-LimpezaTmp').start()

    def _bootstrap_inicial(self):
        try:
            nos = self._carregar_nos()
            if not nos:
                self.atualizar_nos_online()
                nos = self._carregar_nos()
            if self._no and nos:
                ok = self._no.bootstrap(nos)
                self._log(f"Bootstrap enviado a {ok}/{len(nos)} nós")
        except Exception as e:
            logger.error(f"tox _bootstrap_inicial: {e}")

    def _bootstrap_periodico(self):
        while self._no is not None:
            for _ in range(1800):
                if self._no is None:
                    return
                time.sleep(1)
            try:
                if self._no and self._no.status_rede() == 0:
                    self._no.bootstrap(self._carregar_nos())
            except Exception as e:
                logger.error(f"tox bootstrap periódico: {e}")

    def _loop_limpeza_tmp(self):
        while self._no is not None:
            try:
                agora = time.time()
                d = self._tmp_dir()
                for nome in os.listdir(d):
                    caminho = os.path.join(d, nome)
                    try:
                        if agora - os.path.getmtime(caminho) > 3600:
                            os.remove(caminho)
                    except OSError:
                        pass
            except Exception as e:
                logger.error(f"tox limpeza tmp: {e}")
            time.sleep(600)

    def ativar(self):
        try:
            if not self._lib_ok():
                return {
                    'sucesso': False,
                    'erro': ('libtoxcore não encontrada. Use '
                             '"Instalar dependências" ou compile o '
                             'c-toxcore.')
                }
            self._garantir_regras_ufw_tox()
            self._iniciar_no()
            self.config['ativo'] = True
            self._salvar()
            return {
                'sucesso': True,
                'mensagem': 'Tox ativado! Aguardando conexão à rede...',
                'endereco': self._no.endereco_hex()
            }
        except Exception as e:
            logger.error(f"tox ativar: {e}")
            self._no = None
            return {'sucesso': False, 'erro': str(e)}

    def restaurar(self):
        """Chamado no boot do RRFS: religa o Tox se estava ativo."""
        try:
            if self.config.get('ativo') and self._no is None:
                r = self.ativar()
                if not r.get('sucesso'):
                    logger.error(f"tox restaurar: {r.get('erro')}")
        except Exception as e:
            logger.error(f"tox restaurar: {e}")

    def desativar(self):
        try:
            with self._lock:
                no, self._no = self._no, None
            for chave in list(self._ssh):
                self._fechar_ssh(chave)
            for chave in list(self._reqs):
                self._limpar_req(chave)
            if no:
                no.parar()
            self._remover_regras_ufw_tox()
            self.config['ativo'] = False
            self._salvar()
            return {'sucesso': True, 'mensagem': 'Tox desativado'}
        except Exception as e:
            logger.error(f"tox desativar: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def reparar_firewall(self):
        try:
            if not self._fw:
                return {'sucesso': False,
                        'erro': 'Firewall não disponível'}
            self._garantir_regras_ufw_tox()
            return {
                'sucesso': True,
                'mensagem': 'Regras Tox recriadas!',
                'problemas': self._fw.diagnosticar_regras_tox(),
                'interface_saida': self._iface_saida(),
            }
        except Exception as e:
            logger.error(f"tox reparar_firewall: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def obter_diagnostico(self):
        try:
            s = self.obter_status()
            return {
                'sucesso': True,
                'lib_ok': s.get('lib_ok'),
                'rodando': s.get('rodando'),
                'rede_texto': s.get('rede_texto'),
                'nos_bootstrap': s.get('nos_bootstrap'),
                'interface_saida': s.get('interface_saida'),
                'fw_problemas': s.get('fw_problemas'),
                'eventos': s.get('eventos'),
                'transferencias_ativas': s.get('transferencias_ativas'),
                'dica': ('Sem internet: o Tox ainda funciona na LAN '
                         '(descoberta local) e reconecta usando os '
                         'nós salvos na identidade.')
            }
        except Exception as e:
            logger.error(f"tox diagnostico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # IDENTIDADE / AMIGOS
    # ══════════════════════════════════════════════════════

    def _exige_rodando(self):
        if self._no is None:
            return {'sucesso': False, 'erro': 'Tox não está ativo'}
        return None

    def renovar_nospam(self):
        e = self._exige_rodando()
        if e:
            return e
        return {'sucesso': True, 'endereco': self._no.renovar_nospam(),
                'mensagem': 'Novo ID gerado (mesma chave, novo nospam).'}

    def reiniciar_identidade(self):
        """Apaga a chave privada e gera identidade totalmente nova."""
        try:
            estava = self._no is not None
            if estava:
                self.desativar()
            if os.path.exists(self.save_path):
                os.remove(self.save_path)
            self.config['pendentes'] = []
            self._salvar()
            if estava:
                self.ativar()
            return {'sucesso': True,
                    'mensagem': 'Identidade recriada. Amigos removidos.',
                    'endereco': self._no.endereco_hex()
                    if self._no else ''}
        except Exception as e:
            logger.error(f"tox reiniciar_identidade: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def adicionar_amigo(self, endereco, mensagem='RRFS'):
        e = self._exige_rodando()
        if e:
            return e
        endereco = (endereco or '').strip()
        if not RE_ADDR.match(endereco):
            return {'sucesso': False,
                    'erro': 'ID Tox inválido (76 caracteres hex)'}
        num, cod = self._no.adicionar_por_endereco(
            bytes.fromhex(endereco), mensagem or 'RRFS'
        )
        if num is None:
            return {'sucesso': False,
                    'erro': f'Falha ao adicionar amigo (código {cod})'}
        return {'sucesso': True, 'mensagem': 'Pedido enviado.',
                'numero': num}

    def remover_amigo(self, numero):
        e = self._exige_rodando()
        if e:
            return e
        try:
            numero = int(numero)
        except (TypeError, ValueError):
            return {'sucesso': False, 'erro': 'Número inválido'}
        for chave in [k for k in self._ssh if k[0] == numero]:
            self._fechar_ssh(chave)
        for chave in [k for k in self._reqs if k[0] == numero]:
            self._limpar_req(chave)
        self._no.remover_amigo(numero)
        return {'sucesso': True, 'mensagem': 'Amigo removido'}

    def definir_aceitar_automatico(self, ativo):
        self.config['aceitar_automatico'] = bool(ativo)
        self._salvar()
        aviso = ''
        if ativo:
            aviso = (' ATENÇÃO: qualquer pessoa que conheça seu ID Tox '
                     'poderá acessar os serviços ativos.')
        return {'sucesso': True,
                'mensagem': 'Aceite automático '
                            + ('ligado.' if ativo else 'desligado.')
                            + aviso}

    def _ao_pedido(self, chave_bytes, texto):
        chave_hex = chave_bytes.hex().upper()
        if self.config.get('aceitar_automatico'):
            num, cod = self._no.aceitar_chave(chave_bytes)
            self._log(f"Amigo aceito (auto): {chave_hex[:16]}... "
                      f"cod={cod}")
            return
        pend = self.config.setdefault('pendentes', [])
        if not any(p['chave'] == chave_hex for p in pend):
            pend.append({'chave': chave_hex, 'mensagem': texto,
                         'data': datetime.now().isoformat()})
            del pend[:-50]
            self._salvar()
        self._log(f"Pedido pendente: {chave_hex[:16]}...")

    def aprovar_pedido(self, chave_hex):
        e = self._exige_rodando()
        if e:
            return e
        chave_hex = (chave_hex or '').upper()
        if not RE_HEX64.match(chave_hex):
            return {'sucesso': False, 'erro': 'Chave inválida'}
        num, cod = self._no.aceitar_chave(bytes.fromhex(chave_hex))
        self.config['pendentes'] = [
            p for p in self.config.get('pendentes', [])
            if p['chave'] != chave_hex
        ]
        self._salvar()
        if num is None:
            return {'sucesso': False,
                    'erro': f'Falha ao aceitar (código {cod})'}
        return {'sucesso': True, 'mensagem': 'Amigo aprovado'}

    def rejeitar_pedido(self, chave_hex):
        chave_hex = (chave_hex or '').upper()
        self.config['pendentes'] = [
            p for p in self.config.get('pendentes', [])
            if p['chave'] != chave_hex
        ]
        self._salvar()
        return {'sucesso': True, 'mensagem': 'Pedido rejeitado'}

    def _ao_amigo(self, numero, status):
        if status == 0:
            for chave in [k for k in self._ssh if k[0] == numero]:
                self._fechar_ssh(chave)
            for chave in [k for k in self._reqs if k[0] == numero]:
                self._limpar_req(chave)

    # ══════════════════════════════════════════════════════
    # BOOTSTRAP
    # ══════════════════════════════════════════════════════

    def _carregar_nos(self):
        try:
            if os.path.exists(self.nos_path):
                with open(self.nos_path, 'r', encoding='utf-8') as f:
                    return [n for n in json.load(f)
                            if RE_HEX64.match(n.get('chave_publica', ''))]
        except Exception as e:
            logger.error(f"tox carregar_nos: {e}")
        return []

    def _salvar_nos(self, nos):
        try:
            with open(self.nos_path, 'w', encoding='utf-8') as f:
                json.dump(nos, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"tox salvar_nos: {e}")

    def listar_nos(self):
        return {'sucesso': True, 'nos': self._carregar_nos()}

    def atualizar_nos_online(self):
        """Busca nós públicos (precisa de internet)."""
        try:
            req = urllib.request.Request(
                'https://nodes.tox.chat/json',
                headers={'User-Agent': 'RRFS-Tox'}
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                dados = json.loads(r.read().decode('utf-8'))
            atuais = self._carregar_nos()
            existentes = {(n['ip'], int(n['porta'])) for n in atuais}
            novos = 0
            for it in dados.get('nodes', []):
                ip = it.get('ipv4')
                chave = (it.get('public_key') or '').upper()
                if (not it.get('status_udp') or not ip or ip == '-'
                        or not RE_HEX64.match(chave)):
                    continue
                porta = int(it.get('port', 33445))
                if (ip, porta) in existentes:
                    continue
                atuais.append({
                    'ip': ip, 'porta': porta, 'chave_publica': chave,
                    'tcp_ports': it.get('tcp_ports') or [],
                    'origem': 'nodes.tox.chat'
                })
                existentes.add((ip, porta))
                novos += 1
            self._salvar_nos(atuais)
            if self._no and atuais:
                self._no.bootstrap(atuais)
            return {'sucesso': True, 'novos': novos,
                    'total': len(atuais),
                    'mensagem': f'{novos} nós novos adicionados'}
        except Exception as e:
            logger.error(f"tox atualizar_nos: {e}")
            return {'sucesso': False,
                    'erro': f'Sem acesso à lista online: {e}'}

    def adicionar_no(self, ip, porta, chave_publica):
        try:
            ip = (ip or '').strip()
            ipaddress.ip_address(ip)
            porta = int(porta)
            chave = (chave_publica or '').strip().upper()
            if not RE_HEX64.match(chave):
                return {'sucesso': False,
                        'erro': 'Chave pública deve ter 64 hex'}
            if not (1 <= porta <= 65535):
                return {'sucesso': False, 'erro': 'Porta inválida'}
            nos = self._carregar_nos()
            nos.append({'ip': ip, 'porta': porta, 'chave_publica': chave,
                        'tcp_ports': [], 'origem': 'manual'})
            self._salvar_nos(nos)
            if self._no:
                self._no.bootstrap([nos[-1]])
            return {'sucesso': True, 'mensagem': 'Nó adicionado'}
        except ValueError:
            return {'sucesso': False, 'erro': 'IP ou porta inválidos'}
        except Exception as e:
            logger.error(f"tox adicionar_no: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_no(self, indice):
        try:
            nos = self._carregar_nos()
            indice = int(indice)
            if 0 <= indice < len(nos):
                nos.pop(indice)
                self._salvar_nos(nos)
            return {'sucesso': True, 'mensagem': 'Nó removido'}
        except Exception as e:
            logger.error(f"tox remover_no: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # SERVIÇOS
    # ══════════════════════════════════════════════════════

    def _validar_servico(self, nome, porta, interface, ip_custom):
        nome = (nome or '').strip()
        if not RE_NOME.match(nome):
            return None, 'Nome inválido (letras, números, espaço, . -)'
        try:
            porta = int(porta)
        except (TypeError, ValueError):
            return None, 'Porta inválida'
        if not (1 <= porta <= 65535):
            return None, 'Porta: 1-65535'
        interface = (interface or 'localhost').strip()
        if interface != 'localhost' and not RE_IFACE.match(interface):
            return None, 'Interface inválida'
        ip_custom = (ip_custom or '').strip()
        if ip_custom:
            try:
                ipaddress.ip_address(ip_custom)
            except ValueError:
                return None, 'IP de destino inválido'
            host = ip_custom
        else:
            host = self._ip_interface(interface)
        return {'nome': nome, 'porta': porta,
                'interface': interface, 'host': host}, None

    def listar_servicos(self):
        return {'sucesso': True,
                'servicos': self.config.get('servicos', [])}

    def adicionar_servico(self, nome, porta, interface='localhost',
                          ip_destino_custom='', tipo='http',
                          esquema='http', comentario=''):
        try:
            v, err = self._validar_servico(nome, porta, interface,
                                           ip_destino_custom)
            if err:
                return {'sucesso': False, 'erro': err}
            if tipo not in ('http', 'ssh'):
                return {'sucesso': False, 'erro': 'Tipo inválido'}
            if esquema not in ('http', 'https'):
                esquema = 'http'
            if any(s['nome'] == v['nome']
                   for s in self.config['servicos']):
                return {'sucesso': False,
                        'erro': f'"{v["nome"]}" já existe'}
            srv = {
                'id': uuid.uuid4().hex[:8], 'nome': v['nome'],
                'tipo': tipo, 'esquema': esquema,
                'interface': v['interface'], 'host': v['host'],
                'porta': v['porta'],
                'comentario': str(comentario or '')[:200],
                'ativo': False, 'builtin': False,
            }
            self.config['servicos'].append(srv)
            self._salvar()
            return {'sucesso': True, 'servico': srv,
                    'mensagem': f'"{v["nome"]}" adicionado '
                                f'({v["host"]}:{v["porta"]}). '
                                f'Ative para publicar.'}
        except Exception as e:
            logger.error(f"tox adicionar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def editar_servico(self, sid, nome, porta, interface='localhost',
                       ip_destino_custom='', esquema=None,
                       comentario=None):
        try:
            for s in self.config['servicos']:
                if s['id'] != sid:
                    continue
                if s.get('builtin'):
                    if comentario is not None:
                        s['comentario'] = str(comentario)[:200]
                    self._salvar()
                    return {'sucesso': True,
                            'mensagem': 'Comentário atualizado'}
                v, err = self._validar_servico(nome, porta, interface,
                                               ip_destino_custom)
                if err:
                    return {'sucesso': False, 'erro': err}
                if any(o['nome'] == v['nome'] and o['id'] != sid
                       for o in self.config['servicos']):
                    return {'sucesso': False,
                            'erro': f'"{v["nome"]}" já existe'}
                s.update({'nome': v['nome'], 'porta': v['porta'],
                          'interface': v['interface'],
                          'host': v['host']})
                if esquema in ('http', 'https'):
                    s['esquema'] = esquema
                if comentario is not None:
                    s['comentario'] = str(comentario)[:200]
                self._host_efetivo.pop(sid, None)
                self._salvar()
                self._sincronizar_regras_servicos()
                return {'sucesso': True,
                        'mensagem': f'"{v["nome"]}" editado'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"tox editar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def remover_servico(self, sid):
        try:
            for i, s in enumerate(self.config['servicos']):
                if s['id'] == sid:
                    if s.get('builtin'):
                        return {'sucesso': False,
                                'erro': 'Serviço padrão não pode '
                                        'ser removido'}
                    self.config['servicos'].pop(i)
                    self._host_efetivo.pop(sid, None)
                    self._salvar()
                    self._sincronizar_regras_servicos()
                    return {'sucesso': True,
                            'mensagem': f'"{s["nome"]}" removido'}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"tox remover_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def alternar_servico(self, sid):
        try:
            for s in self.config['servicos']:
                if s['id'] == sid:
                    s['ativo'] = not s.get('ativo', False)
                    self._salvar()
                    self._sincronizar_regras_servicos()
                    return {'sucesso': True, 'ativo': s['ativo'],
                            'mensagem': f'"{s["nome"]}" '
                                        + ('ativado' if s['ativo']
                                           else 'desativado')}
            return {'sucesso': False, 'erro': 'Não encontrado'}
        except Exception as e:
            logger.error(f"tox alternar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    def importar_servicos(self, servicos):
        ok = err = 0
        for s in servicos or []:
            if s.get('builtin'):
                continue
            r = self.adicionar_servico(
                s.get('nome', ''), s.get('porta', 80),
                s.get('interface', 'localhost'),
                s.get('host', '') if s.get('interface') != 'localhost'
                else '',
                s.get('tipo', 'http'), s.get('esquema', 'http'),
                s.get('comentario', '')
            )
            if r.get('sucesso'):
                ok += 1
            else:
                err += 1
        return {'sucesso': True,
                'mensagem': f'{ok} serviços importados, {err} erros'}

    def _servico_ativo(self, sid, tipo):
        for s in self.config.get('servicos', []):
            if s['id'] == sid and s.get('ativo') and s['tipo'] == tipo:
                return s
        return None

    def _hosts_candidatos(self, srv):
        """Host cadastrado primeiro; se o serviço é DESTA máquina,
        também 127.0.0.1 e os IPs locais (o app pode escutar só em um
        deles). Host remoto da LAN: só ele mesmo."""
        host = srv['host']
        locais = _ips_locais()
        if host in locais or host.startswith('127.'):
            cands = ([self._host_efetivo.get(srv['id'], host), host,
                      '127.0.0.1'] + sorted(locais))
        else:
            cands = [host]
        vistos, saida = set(), []
        for c in cands:
            if c and c not in vistos:
                vistos.add(c)
                saida.append(c)
        return saida

    def testar_servico(self, sid):
        """Diagnóstico: tenta conectar em cada host candidato e lista
        as portas TCP que estão realmente escutando no servidor."""
        try:
            srv = next((s for s in self.config.get('servicos', [])
                        if s['id'] == sid), None)
            if not srv:
                return {'sucesso': False, 'erro': 'Não encontrado'}
            resultados = []
            for h in self._hosts_candidatos(srv):
                t0 = time.time()
                try:
                    with socket.create_connection(
                            (h, int(srv['porta'])), timeout=3):
                        ok, err = True, ''
                except OSError as e:
                    ok, err = False, str(e)
                resultados.append({
                    'host': h, 'porta': srv['porta'], 'ok': ok,
                    'erro': err,
                    'ms': int((time.time() - t0) * 1000)})
            r = executar_comando(
                "ss -ltnH 2>/dev/null | awk '{print $4}' | "
                "sort -u | head -80", timeout=5
            )
            return {
                'sucesso': True, 'servico': srv['nome'],
                'resultados': resultados,
                'portas_escutando': (r['saida'].splitlines()
                                     if r['sucesso'] else []),
                'dica': ('Se todos falharam, nada escuta nessa porta: '
                         'confira a porta PUBLICADA do container '
                         '(docker ps) e o esquema http/https.')
            }
        except Exception as e:
            logger.error(f"tox testar_servico: {e}")
            return {'sucesso': False, 'erro': str(e)}

    # ══════════════════════════════════════════════════════
    # UFW
    # ══════════════════════════════════════════════════════

    def _garantir_regras_ufw_tox(self):
        fw = self._fw
        if not fw:
            logger.error("tox: firewall não definido")
            return False
        try:
            from modulos.firewall_ufw import FirewallUFW
            cat   = FirewallUFW.CAT_TOX
            iface = self._iface_saida()
            fw.remover_regras_prefixo(cat, 'Tox:infra:')

            def regra(nome, direcao, proto, porta, interface=iface):
                fw.adicionar_regra_automatica(nome, {
                    'nome': nome, 'interface': interface,
                    'direcao': direcao, 'protocolo': proto,
                    'ip': '', 'porta': porta
                }, cat)

            regra('Tox:infra:saida:udp', 'out', 'udp', '')
            for p in ('443', '3389', '33445'):
                regra(f'Tox:infra:saida:tcp:{p}', 'out', 'tcp', p)
            regra('Tox:infra:entrada:udp', 'in', 'udp',
                  f'{PORTA_UDP_INICIO}:{PORTA_UDP_FIM}')

            self._sincronizar_regras_servicos()
            return True
        except Exception as e:
            logger.error(f"tox _garantir_regras_ufw: {e}")
            return False

    def _sincronizar_regras_servicos(self):
        """Regras de destino só existem para serviços ATIVOS."""
        fw = self._fw
        if not fw:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            cat = FirewallUFW.CAT_TOX
            fw.remover_regras_prefixo(cat, 'Tox:srv:')
            if not self.config.get('ativo') and self._no is None:
                return
            for s in self.config.get('servicos', []):
                if not s.get('ativo'):
                    continue
                host, porta = s['host'], str(s['porta'])
                nome = f"Tox:srv:{s['nome']}"
                if host.startswith('127.'):
                    fw.adicionar_regra_automatica(nome, {
                        'nome': nome, 'interface': 'lo',
                        'direcao': 'in', 'protocolo': 'tcp',
                        'ip': '127.0.0.0/8', 'porta': porta
                    }, cat)
                else:
                    # v3.0: saída em QUALQUER interface (IP de
                    # container Docker vai por docker0/br-*, não pela
                    # interface da LAN). Respostas voltam por conntrack.
                    iface = (s['interface']
                             if s['interface'] not in ('', 'localhost')
                             else '')
                    fw.adicionar_regra_automatica(nome, {
                        'nome': nome, 'interface': iface,
                        'direcao': 'out', 'protocolo': 'tcp',
                        'ip': host, 'porta': porta
                    }, cat)
        except Exception as e:
            logger.error(f"tox _sincronizar_regras: {e}")

    def _remover_regras_ufw_tox(self):
        fw = self._fw
        if not fw:
            return
        try:
            from modulos.firewall_ufw import FirewallUFW
            fw.remover_regras_prefixo(FirewallUFW.CAT_TOX, 'Tox:')
        except Exception as e:
            logger.error(f"tox _remover_regras_ufw: {e}")

    # ══════════════════════════════════════════════════════
    # DESPACHO DE MENSAGENS DOS CLIENTES
    # ══════════════════════════════════════════════════════

    def _ao_mensagem(self, numero, msg):
        tipo = msg.get('tipo') if isinstance(msg, dict) else None
        try:
            if tipo == 'listar_servicos':
                lista = [{'id': s['id'], 'nome': s['nome'],
                          'tipo': s['tipo'],
                          'comentario': s.get('comentario', '')}
                         for s in self.config.get('servicos', [])
                         if s.get('ativo')]
                self._enviar(numero, {'tipo': 'lista_servicos',
                                      'dados': lista})
            elif tipo == 'http_abrir':
                self._http_abrir(numero, msg)
            elif tipo == 'http_corpo':
                self._http_corpo(numero, msg)
            elif tipo == 'http_corpo_fim':
                self._http_corpo_fim(numero, msg)
            elif tipo == 'http_cancelar':
                self._http_cancelar(numero, msg)
            elif tipo == 'ssh_abrir':
                self._ssh_abrir(numero, msg)
            elif tipo == 'ssh_dados':
                par = self._ssh.get((numero, msg.get('session_id')))
                if par:
                    par[1].send(base64.b64decode(msg.get('dados', '')))
            elif tipo == 'ssh_fechar':
                self._fechar_ssh((numero, msg.get('session_id')))
        except Exception as e:
            logger.error(f"tox mensagem '{tipo}': {e}")

    def _enviar(self, numero, msg, cancelado=None):
        no = self._no
        if no:
            no.enviar(numero, msg, cancelado=cancelado)

    # ══════════════════════════════════════════════════════
    # PROXY HTTP EM STREAMING
    #
    # cliente -> servidor:
    #   http_abrir {id, service_id, method, path, headers, tem_corpo}
    #   http_corpo {id, dados(b64)} ... http_corpo_fim {id}  (se corpo)
    #   http_cancelar {id}
    # servidor -> cliente:
    #   http_resposta_inicio {id, status, headers}
    #   http_resposta_dados {id, dados(b64)} (N vezes)
    #   http_resposta_fim {id} | http_resposta_erro {id, mensagem}
    # ══════════════════════════════════════════════════════

    def _limpar_req(self, chave):
        reg = self._reqs.pop(chave, None)
        if not reg:
            return
        if reg.get('fh'):
            try:
                reg['fh'].close()
            except Exception:
                pass
        if reg.get('arquivo'):
            try:
                os.remove(reg['arquivo'])
            except OSError:
                pass

    def _iniciar_proxy(self, numero, req_id):
        threading.Thread(
            target=self._processar_proxy, args=(numero, req_id),
            daemon=True, name='Tox-HTTP'
        ).start()

    def _http_abrir(self, numero, msg):
        req_id = msg.get('id')
        if not req_id:
            return
        chave = (numero, req_id)

        if len([k for k in self._reqs if k[0] == numero]) \
                >= MAX_REQS_SIMULTANEAS_POR_AMIGO:
            self._enviar(numero, {
                'tipo': 'http_resposta_erro', 'id': req_id,
                'mensagem': 'Muitas transferências simultâneas'
            })
            return

        meta = {
            'metodo': str(msg.get('method', 'GET')).upper(),
            'path': str(msg.get('path', '/')),
            'headers': msg.get('headers') or {},
            'service_id': msg.get('service_id'),
        }
        reg = {
            'meta': meta, 'arquivo': None, 'fh': None,
            'tam': 0, 'cancelado': threading.Event(),
            'iniciado': False,
        }

        if msg.get('tem_corpo'):
            try:
                fd, caminho = tempfile.mkstemp(
                    prefix='corpo_', dir=self._tmp_dir()
                )
                os.close(fd)
                reg['arquivo'] = caminho
                reg['fh'] = open(caminho, 'ab')
            except Exception as e:
                logger.error(f"tox http_abrir temp: {e}")
                self._enviar(numero, {
                    'tipo': 'http_resposta_erro', 'id': req_id,
                    'mensagem': 'Erro interno no servidor (disco)'
                })
                return
            self._reqs[chave] = reg
        else:
            reg['iniciado'] = True      # v3.0: nunca iniciar 2x
            self._reqs[chave] = reg
            self._iniciar_proxy(numero, req_id)

    def _http_corpo(self, numero, msg):
        chave = (numero, msg.get('id'))
        reg = self._reqs.get(chave)
        if not reg or not reg.get('fh'):
            return
        try:
            bloco = base64.b64decode(msg.get('dados', ''))
        except Exception:
            return
        reg['tam'] += len(bloco)
        if reg['tam'] > TAM_MAX_CORPO_DISCO:
            logger.error("tox http corpo: limite de upload excedido")
            self._enviar(numero, {
                'tipo': 'http_resposta_erro', 'id': msg.get('id'),
                'mensagem': 'Arquivo excede o limite do servidor'
            })
            self._limpar_req(chave)
            return
        try:
            reg['fh'].write(bloco)
        except Exception as e:
            logger.error(f"tox http corpo write: {e}")

    def _http_corpo_fim(self, numero, msg):
        chave = (numero, msg.get('id'))
        with self._lock:
            reg = self._reqs.get(chave)
            # v3.0: ignora se já iniciado (evita a 2ª thread que
            # duplicava dados) ou se foi cancelado.
            if not reg or reg.get('iniciado') or \
                    reg['cancelado'].is_set():
                return
            reg['iniciado'] = True
        if reg.get('fh'):
            try:
                reg['fh'].close()
            except Exception:
                pass
            reg['fh'] = None
        self._iniciar_proxy(numero, msg.get('id'))

    def _http_cancelar(self, numero, msg):
        chave = (numero, msg.get('id'))
        with self._lock:
            reg = self._reqs.get(chave)
            if not reg:
                return
            reg['cancelado'].set()
            ja_iniciado = reg.get('iniciado')
        if not ja_iniciado:
            # upload interrompido: descarta (nunca processar parcial)
            self._limpar_req(chave)

    def _nova_conexao(self, srv, host):
        if srv['esquema'] == 'https':
            return http.client.HTTPSConnection(
                host, srv['porta'], timeout=TIMEOUT_CONECTAR_BACKEND,
                context=ssl._create_unverified_context()
            )
        return http.client.HTTPConnection(
            host, srv['porta'], timeout=TIMEOUT_CONECTAR_BACKEND
        )

    def _conectar_e_enviar(self, srv, metodo, caminho, cab,
                           arquivo, tam_corpo, reg):
        """Conecta ao backend (host cadastrado + alternativos locais),
        envia cabeçalhos e corpo. Retry com backoff em recusa
        transitória. Retorna (conexão, host_usado)."""
        candidatos = self._hosts_candidatos(srv)
        ultimo_erro = None
        for rodada in range(RETRY_CONEXAO_RECUSADA):
            for host in candidatos:
                if reg['cancelado'].is_set():
                    raise RuntimeError('Cancelado pelo cliente')
                conn = None
                try:
                    conn = self._nova_conexao(srv, host)
                    # skip_accept_encoding: usamos o do cliente (se
                    # houver) sem duplicar o cabeçalho.
                    conn.putrequest(metodo, caminho, skip_host=False,
                                    skip_accept_encoding=True)
                    for k, v in cab.items():
                        conn.putheader(k, v)
                    if arquivo and tam_corpo > 0:
                        conn.putheader('Content-Length',
                                       str(tam_corpo))
                    conn.endheaders()

                    if arquivo and tam_corpo > 0:
                        with open(arquivo, 'rb') as f:
                            while True:
                                if reg['cancelado'].is_set():
                                    raise RuntimeError(
                                        'Cancelado pelo cliente')
                                bloco = f.read(TAM_BLOCO_STREAM)
                                if not bloco:
                                    break
                                conn.send(bloco)

                    if self._host_efetivo.get(srv['id']) != host:
                        self._host_efetivo[srv['id']] = host
                    return conn, host

                except (ConnectionRefusedError,
                        ConnectionResetError) as e:
                    ultimo_erro = e
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    continue
                except Exception:
                    if conn:
                        try:
                            conn.close()
                        except Exception:
                            pass
                    raise
            if rodada < RETRY_CONEXAO_RECUSADA - 1:
                time.sleep(RETRY_CONEXAO_ESPERAS[
                    min(rodada, len(RETRY_CONEXAO_ESPERAS) - 1)])
        raise ultimo_erro or RuntimeError('Falha ao conectar ao serviço')

    def _processar_proxy(self, numero, req_id):
        """Thread própria: conecta no serviço local, envia o corpo
        (do disco) e repassa a resposta em tempo real. QUALQUER falha
        aborta a transferência com erro (nunca 'fim' falso)."""
        chave = (numero, req_id)
        reg = self._reqs.get(chave)
        if not reg:
            return
        meta = reg['meta']

        def enviar(tipo, **campos):
            self._enviar(numero, {'tipo': tipo, 'id': req_id,
                                  **campos}, cancelado=reg['cancelado'])

        def enviar_erro(mensagem):
            try:
                self._enviar(numero, {'tipo': 'http_resposta_erro',
                                      'id': req_id,
                                      'mensagem': mensagem})
            except Exception:
                pass

        srv = self._servico_ativo(meta['service_id'], 'http')
        if not srv:
            enviar_erro('Serviço indisponível')
            self._limpar_req(chave)
            return

        caminho = meta['path']
        if not caminho.startswith('/'):
            enviar_erro('Caminho inválido')
            self._limpar_req(chave)
            return
        try:
            caminho = _normalizar_caminho_http(caminho)
        except Exception as e:
            logger.error(f"tox normalizar caminho '{meta['path']}': {e}")
            enviar_erro('Caminho inválido')
            self._limpar_req(chave)
            return

        metodo = meta['metodo']
        if metodo not in ('GET', 'POST', 'PUT', 'DELETE', 'HEAD',
                          'PATCH', 'OPTIONS'):
            enviar_erro('Método não permitido')
            self._limpar_req(chave)
            return

        origem_backend = (f"{srv['esquema']}://{srv['host']}:"
                          f"{srv['porta']}")
        ocultos = {'host', 'connection', 'keep-alive', 'content-length',
                   'transfer-encoding', 'upgrade', 'expect'}
        cab = {}
        hs = meta.get('headers') or {}
        itens = hs.items() if isinstance(hs, dict) else hs
        for k, v in itens:
            kl = str(k).lower()
            if kl in ocultos:
                continue
            v = _sanitizar_valor_cabecalho(v)
            if kl == 'origin':
                v = origem_backend
            elif kl == 'referer':
                v = re.sub(r'^https?://[^/]+', origem_backend, v)
            cab[str(k)] = v

        arquivo = reg.get('arquivo')
        tam_corpo = reg.get('tam', 0)

        sem = self._semaforo_servico(srv['id'])
        if not sem.acquire(timeout=TIMEOUT_ESPERAR_VAGA_CONEXAO):
            enviar_erro('Serviço local sobrecarregado (muitas conexões '
                        'simultâneas). Tente novamente em instantes.')
            self._limpar_req(chave)
            return

        conn = None
        try:
            conn, _host = self._conectar_e_enviar(
                srv, metodo, caminho, cab, arquivo, tam_corpo, reg
            )

            if conn.sock:
                conn.sock.settimeout(TIMEOUT_ESPERAR_CABECALHOS)
            resposta = conn.getresponse()

            hosts_loc = ({h.lower() for h in
                          self._hosts_candidatos(srv)} | {'localhost'})
            cabecalhos = []
            esperado = None
            for k, v in resposta.getheaders():
                kl = k.lower()
                if kl in ('transfer-encoding', 'connection',
                          'keep-alive'):
                    continue
                if kl == 'location':
                    v = _reescrever_location(v, hosts_loc)
                elif kl == 'set-cookie':
                    v = _ajustar_set_cookie(v)
                elif kl == 'content-length':
                    try:
                        esperado = int(v)
                    except ValueError:
                        pass
                cabecalhos.append([k, v])
            if (metodo == 'HEAD' or resposta.status in (204, 304) or
                    100 <= resposta.status < 200):
                esperado = None

            enviar('http_resposta_inicio', status=resposta.status,
                   headers=cabecalhos)

            if conn.sock:
                conn.sock.settimeout(TIMEOUT_LEITURA_SEM_DADOS)
            total = 0
            while True:
                if reg['cancelado'].is_set():
                    break
                # read1: devolve o que já chegou (não espera encher)
                bloco = resposta.read1(TAM_BLOCO_STREAM)
                if not bloco:
                    break
                total += len(bloco)
                enviar('http_resposta_dados',
                       dados=base64.b64encode(bloco).decode())

            if not reg['cancelado'].is_set():
                if esperado is not None and total != esperado:
                    raise RuntimeError(
                        f'Resposta incompleta do serviço local '
                        f'({total}/{esperado} bytes)')
                enviar('http_resposta_fim')

        except Exception as e:
            if not reg['cancelado'].is_set():
                logger.error(f"tox proxy http {meta.get('path')}: {e}")
                if isinstance(e, ConnectionRefusedError):
                    enviar_erro(
                        f"Conexão recusada em {srv['host']}:"
                        f"{srv['porta']} (nada escutando nessa porta). "
                        f"Confira porta/IP/esquema do serviço "
                        f"(use 'testar serviço' ou 'ss -ltnp').")
                else:
                    enviar_erro(f'Erro no serviço local: {e}')
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
            sem.release()
            self._limpar_req(chave)

    # ══════════════════════════════════════════════════════
    # SSH (inalterado)
    # ══════════════════════════════════════════════════════

    def _ssh_abrir(self, numero, msg):
        sid = msg.get('session_id')
        chave = (numero, sid)

        def erro(txt):
            self._enviar(numero, {'tipo': 'ssh_erro',
                                  'session_id': sid, 'mensagem': txt})

        if not PARAMIKO_OK:
            return erro('paramiko não instalado no servidor')
        srv = next((s for s in self.config.get('servicos', [])
                    if s['tipo'] == 'ssh' and s.get('ativo')), None)
        if not srv:
            return erro('SSH desativado no servidor')
        if len([k for k in self._ssh if k[0] == numero]) >= 3:
            return erro('Limite de sessões SSH atingido')
        try:
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            cli.connect(srv['host'], port=srv['porta'],
                        username=msg.get('usuario'),
                        password=msg.get('senha'), timeout=10,
                        allow_agent=False, look_for_keys=False)
            canal = cli.invoke_shell(term='xterm')
            canal.settimeout(0.0)
            self._ssh[chave] = (cli, canal)
            self._enviar(numero, {'tipo': 'ssh_aberto',
                                  'session_id': sid})
        except Exception as e:
            return erro(str(e))

        def ler():
            try:
                while chave in self._ssh and not canal.closed:
                    if canal.recv_ready():
                        d = canal.recv(2048)
                        if not d:
                            break
                        self._enviar(numero, {
                            'tipo': 'ssh_dados', 'session_id': sid,
                            'dados': base64.b64encode(d).decode()
                        })
                    else:
                        time.sleep(0.03)
            except Exception:
                pass
            finally:
                self._fechar_ssh(chave)
                try:
                    self._enviar(numero, {'tipo': 'ssh_fechado',
                                          'session_id': sid})
                except Exception:
                    pass

        threading.Thread(target=ler, daemon=True,
                         name='Tox-SSH').start()

    def _fechar_ssh(self, chave):
        par = self._ssh.pop(chave, None)
        if par:
            for obj in (par[1], par[0]):
                try:
                    obj.close()
                except Exception:
                    pass
