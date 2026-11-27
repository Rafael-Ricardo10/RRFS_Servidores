#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Importar / Exportar configurações - RRFS Servidores v2.0
"""

import os
import json
import logging
import tempfile
from datetime import datetime

logger = logging.getLogger('RRFS.ConfigIO')

CATEGORIAS_DISPONIVEIS = [
    'ufw_regras',
    'tor_servicos',
    'vpns_saida',
    'vpn_acesso',
    'dns_config',
    'av_config',
    'conexao_wan',
]


def exportar_configuracoes(base_dir, categorias=None):
    """Exporta configurações selecionadas para JSON"""
    try:
        if not categorias:
            categorias = CATEGORIAS_DISPONIVEIS

        dados_dir = os.path.join(base_dir, 'dados')
        export    = {
            'versao':     '2.0',
            'exportado_em': datetime.now().isoformat(),
            'sistema':    'RRFS Servidores',
            'categorias': {}
        }

        # ── UFW regras ─────────────────────────────────
        if 'ufw_regras' in categorias:
            path = os.path.join(dados_dir, 'regras_ufw.json')
            if os.path.exists(path):
                with open(path, 'r') as f:
                    regras = json.load(f)
                # exportar apenas regras do usuário
                export['categorias']['ufw_regras'] = [
                    r for r in regras
                    if r.get('categoria') == 'usuario'
                ]

        # ── Tor serviços ───────────────────────────────
        if 'tor_servicos' in categorias:
            path = os.path.join(dados_dir, 'tor_config.json')
            if os.path.exists(path):
                with open(path, 'r') as f:
                    tor = json.load(f)
                # não exportar dir_id (onion será regenerado)
                servicos_export = []
                for s in tor.get('servicos', []):
                    sc = dict(s)
                    sc.pop('dir_id', None)
                    sc.pop('onion', None)
                    servicos_export.append(sc)
                export['categorias']['tor_servicos'] = \
                    servicos_export

        # ── VPNs de saída (com credenciais) ────────────
        if 'vpns_saida' in categorias:
            path = os.path.join(
                dados_dir, 'conexao', 'vpns.json'
            )
            if os.path.exists(path):
                with open(path, 'r') as f:
                    vpns = json.load(f)

                vpns_export = []
                for v in vpns:
                    ve = dict(v)
                    # incluir conteúdo do arquivo .ovpn
                    arq = v.get('arquivo', '')
                    if arq and os.path.exists(arq):
                        try:
                            with open(arq, 'r') as fv:
                                ve['ovpn_conteudo'] = fv.read()
                        except Exception:
                            pass
                    # incluir credenciais
                    arq_auth = v.get('arquivo_auth', '')
                    if arq_auth and os.path.exists(arq_auth):
                        try:
                            with open(arq_auth, 'r') as fa:
                                ve['auth_conteudo'] = fa.read()
                        except Exception:
                            pass
                    ve.pop('arquivo', None)
                    ve.pop('arquivo_auth', None)
                    ve['ativa'] = False
                    vpns_export.append(ve)

                export['categorias']['vpns_saida'] = vpns_export

        # ── VPN acesso ─────────────────────────────────
        if 'vpn_acesso' in categorias:
            path = os.path.join(
                dados_dir, 'conexao', 'vpn_acesso.json'
            )
            if os.path.exists(path):
                with open(path, 'r') as f:
                    export['categorias']['vpn_acesso'] = \
                        json.load(f)

        # ── DNS config ─────────────────────────────────
        if 'dns_config' in categorias:
            path = os.path.join(dados_dir, 'dns_config.json')
            if os.path.exists(path):
                with open(path, 'r') as f:
                    export['categorias']['dns_config'] = \
                        json.load(f)

        # ── AV config ──────────────────────────────────
        if 'av_config' in categorias:
            path = os.path.join(dados_dir, 'av_config.json')
            if os.path.exists(path):
                with open(path, 'r') as f:
                    cfg = json.load(f)
                # não exportar estado de scan
                cfg.pop('scan_info', None)
                export['categorias']['av_config'] = cfg

        # ── Conexão WAN ────────────────────────────────
        if 'conexao_wan' in categorias:
            path = os.path.join(
                dados_dir, 'conexao', 'config.json'
            )
            if os.path.exists(path):
                with open(path, 'r') as f:
                    cfg = json.load(f)
                # não exportar estado de VPN ativa
                cfg.pop('forma_ativa_em', None)
                export['categorias']['conexao_wan'] = cfg

        # salvar em arquivo temporário
        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json',
            prefix='rrfs_export_',
            delete=False,
            encoding='utf-8'
        )
        json.dump(export, tmp, indent=2, ensure_ascii=False)
        tmp.close()

        return {
            'sucesso':   True,
            'arquivo':   tmp.name,
            'categorias': list(export['categorias'].keys()),
            'total':      sum(
                len(v) if isinstance(v, list) else 1
                for v in export['categorias'].values()
            )
        }

    except Exception as e:
        logger.error(f"exportar_configuracoes: {e}")
        return {'sucesso': False, 'erro': str(e)}


def preview_importacao(conteudo_json):
    """Retorna preview do que será importado"""
    try:
        dados = json.loads(conteudo_json)
        cats  = dados.get('categorias', {})

        preview = {
            'sucesso':      True,
            'versao':       dados.get('versao', '--'),
            'exportado_em': dados.get('exportado_em', '--'),
            'categorias':   {}
        }

        for cat, val in cats.items():
            if isinstance(val, list):
                preview['categorias'][cat] = {
                    'total': len(val),
                    'itens': [
                        _resumo_item(cat, item)
                        for item in val[:5]
                    ]
                }
            else:
                preview['categorias'][cat] = {
                    'total': 1,
                    'itens': [str(val)[:100]]
                }

        return preview
    except json.JSONDecodeError:
        return {
            'sucesso': False,
            'erro': 'Arquivo JSON inválido'
        }
    except Exception as e:
        logger.error(f"preview_importacao: {e}")
        return {'sucesso': False, 'erro': str(e)}


def _resumo_item(categoria, item):
    """Gerar resumo legível de um item"""
    if categoria == 'ufw_regras':
        return (
            f"{item.get('nome','?')} | "
            f"{item.get('direcao','?')} | "
            f"porta {item.get('porta','?')}"
        )
    elif categoria == 'tor_servicos':
        return (
            f"{item.get('nome','?')} | "
            f":{item.get('porta_virtual','?')} → "
            f":{item.get('porta_destino','?')}"
        )
    elif categoria == 'vpns_saida':
        return (
            f"{item.get('nome','?')} | "
            f"{item.get('ip_servidor','?')}:"
            f"{item.get('porta','?')}"
        )
    return str(item)[:80]


def importar_configuracoes(base_dir, conteudo_json,
                            categorias_selecionadas,
                            firewall, tor, conexao):
    """Importa configurações selecionadas"""
    try:
        dados     = json.loads(conteudo_json)
        cats      = dados.get('categorias', {})
        dados_dir = os.path.join(base_dir, 'dados')
        resultados = {}

        for cat in categorias_selecionadas:
            if cat not in cats:
                continue

            try:
                if cat == 'ufw_regras':
                    resultados[cat] = _importar_ufw(
                        cats[cat], firewall
                    )

                elif cat == 'tor_servicos':
                    resultados[cat] = _importar_tor(
                        cats[cat], tor
                    )

                elif cat == 'vpns_saida':
                    resultados[cat] = _importar_vpns(
                        cats[cat], conexao
                    )

                elif cat == 'vpn_acesso':
                    resultados[cat] = _importar_json(
                        os.path.join(
                            dados_dir,
                            'conexao', 'vpn_acesso.json'
                        ),
                        cats[cat]
                    )

                elif cat == 'dns_config':
                    resultados[cat] = _importar_json(
                        os.path.join(
                            dados_dir, 'dns_config.json'
                        ),
                        cats[cat]
                    )

                elif cat == 'av_config':
                    resultados[cat] = _importar_json(
                        os.path.join(
                            dados_dir, 'av_config.json'
                        ),
                        cats[cat]
                    )

                elif cat == 'conexao_wan':
                    resultados[cat] = _importar_json(
                        os.path.join(
                            dados_dir,
                            'conexao', 'config.json'
                        ),
                        cats[cat]
                    )

            except Exception as e:
                logger.error(f"importar {cat}: {e}")
                resultados[cat] = {
                    'sucesso': False, 'erro': str(e)
                }

        return {
            'sucesso':    True,
            'resultados': resultados,
            'mensagem':   (
                f'{len(resultados)} categorias importadas!'
            )
        }

    except json.JSONDecodeError:
        return {'sucesso': False, 'erro': 'JSON inválido'}
    except Exception as e:
        logger.error(f"importar_configuracoes: {e}")
        return {'sucesso': False, 'erro': str(e)}


def _importar_ufw(regras, firewall):
    ok = err = 0
    for r in regras:
        r.pop('id', None)
        r['categoria'] = 'usuario'
        r['editavel']  = True
        res = firewall.adicionar_regra(r)
        if res.get('sucesso'):
            ok += 1
        else:
            err += 1
    return {
        'sucesso': True,
        'mensagem': f'{ok} regras importadas, {err} erros'
    }


def _importar_tor(servicos, tor):
    ok = err = 0
    for s in servicos:
        res = tor.adicionar_servico(
            s.get('nome', ''),
            s.get('porta_virtual', 80),
            s.get('porta_destino', 80),
            s.get('interface', 'localhost')
        )
        if res.get('sucesso'):
            ok += 1
        else:
            err += 1
    return {
        'sucesso': True,
        'mensagem': f'{ok} serviços importados, {err} erros'
    }


def _importar_vpns(vpns, conexao):
    ok = err = 0
    for v in vpns:
        ovpn = v.get('ovpn_conteudo', '')
        if not ovpn:
            err += 1
            continue
        usuario = v.get('usuario', '')
        senha   = ''
        auth    = v.get('auth_conteudo', '')
        if auth:
            linhas = auth.strip().splitlines()
            if len(linhas) >= 2:
                usuario = linhas[0]
                senha   = linhas[1]
        res = conexao.importar_vpn_saida(
            v.get('nome', 'VPN Importada'),
            ovpn, usuario, senha
        )
        if res.get('sucesso'):
            ok += 1
        else:
            err += 1
    return {
        'sucesso': True,
        'mensagem': f'{ok} VPNs importadas, {err} erros'
    }


def _importar_json(path, dados):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # mesclar com existente
        existente = {}
        if os.path.exists(path):
            with open(path, 'r') as f:
                existente = json.load(f)
        existente.update(dados)
        with open(path, 'w') as f:
            json.dump(existente, f,
                      indent=2, ensure_ascii=False)
        return {'sucesso': True, 'mensagem': 'Importado'}
    except Exception as e:
        logger.error(f"_importar_json {path}: {e}")
        return {'sucesso': False, 'erro': str(e)}
