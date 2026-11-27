#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Importar / Exportar configurações - RRFS Servidores v2.1
v2.1: categorias de VPN removidas; adicionada 'tox_servicos'.
      A identidade Tox (chave privada) NUNCA é exportada.
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
    'tox_servicos',
    'dns_config',
    'av_config',
]

# chaves de estado que não devem ser restauradas por importação
_IGNORAR_NA_IMPORTACAO = {
    'dns_config': ('ativo',),
    'av_config':  ('instalado', 'ultimo_scan_completo',
                   'ultimo_scan_diario', 'ultimo_update_db'),
}


def _ler_json(path, padrao=None):
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"_ler_json {path}: {e}")
    return padrao


def exportar_configuracoes(base_dir, categorias=None):
    """Exporta configurações selecionadas para JSON"""
    try:
        if not categorias:
            categorias = CATEGORIAS_DISPONIVEIS

        dados_dir = os.path.join(base_dir, 'dados')
        export = {
            'versao':       '2.1',
            'exportado_em': datetime.now().isoformat(),
            'sistema':      'RRFS Servidores',
            'categorias':   {}
        }
        cats = export['categorias']

        if 'ufw_regras' in categorias:
            regras = _ler_json(
                os.path.join(dados_dir, 'regras_ufw.json'), []
            )
            cats['ufw_regras'] = [
                r for r in regras if r.get('categoria') == 'usuario'
            ]

        if 'tor_servicos' in categorias:
            tor = _ler_json(
                os.path.join(dados_dir, 'tor_config.json'), None
            )
            if tor is not None:
                servicos = []
                for s in tor.get('servicos', []):
                    sc = dict(s)
                    sc.pop('dir_id', None)   # onion será regenerado
                    sc.pop('onion', None)
                    servicos.append(sc)
                cats['tor_servicos'] = servicos

        if 'tox_servicos' in categorias:
            tox = _ler_json(
                os.path.join(dados_dir, 'tox', 'config.json'), None
            )
            if tox is not None:
                cats['tox_servicos'] = [
                    {k: v for k, v in s.items() if k != 'ativo'}
                    for s in tox.get('servicos', [])
                    if not s.get('builtin')
                ]

        for cat, arq in (('dns_config', 'dns_config.json'),
                         ('av_config',  'av_config.json')):
            if cat in categorias:
                cfg = _ler_json(os.path.join(dados_dir, arq), None)
                if cfg is not None:
                    cfg.pop('scan_info', None)
                    cats[cat] = cfg

        tmp = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', prefix='rrfs_export_',
            delete=False, encoding='utf-8'
        )
        json.dump(export, tmp, indent=2, ensure_ascii=False)
        tmp.close()
        os.chmod(tmp.name, 0o600)

        return {
            'sucesso':    True,
            'arquivo':    tmp.name,
            'categorias': list(cats.keys()),
            'total':      sum(len(v) if isinstance(v, list) else 1
                              for v in cats.values())
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
            if cat not in CATEGORIAS_DISPONIVEIS:
                continue   # categorias antigas (VPN/WAN) são ignoradas
            if isinstance(val, list):
                preview['categorias'][cat] = {
                    'total': len(val),
                    'itens': [_resumo_item(cat, i) for i in val[:5]]
                }
            else:
                preview['categorias'][cat] = {
                    'total': 1, 'itens': [str(val)[:100]]
                }
        return preview
    except json.JSONDecodeError:
        return {'sucesso': False, 'erro': 'Arquivo JSON inválido'}
    except Exception as e:
        logger.error(f"preview_importacao: {e}")
        return {'sucesso': False, 'erro': str(e)}


def _resumo_item(categoria, item):
    if categoria == 'ufw_regras':
        return (f"{item.get('nome','?')} | {item.get('direcao','?')} "
                f"| porta {item.get('porta','?')}")
    if categoria == 'tor_servicos':
        return (f"{item.get('nome','?')} | "
                f":{item.get('porta_virtual','?')} → "
                f"{item.get('ip_destino','')}:"
                f"{item.get('porta_destino','?')}")
    if categoria == 'tox_servicos':
        return (f"{item.get('nome','?')} | {item.get('tipo','?')} | "
                f"{item.get('host','')}:{item.get('porta','?')}")
    return str(item)[:80]


def importar_configuracoes(base_dir, conteudo_json,
                           categorias_selecionadas,
                           firewall, tor, tox):
    """Importa configurações selecionadas"""
    try:
        dados      = json.loads(conteudo_json)
        cats       = dados.get('categorias', {})
        dados_dir  = os.path.join(base_dir, 'dados')
        resultados = {}

        for cat in categorias_selecionadas:
            if cat not in CATEGORIAS_DISPONIVEIS or cat not in cats:
                continue
            try:
                if cat == 'ufw_regras':
                    resultados[cat] = _importar_ufw(cats[cat], firewall)
                elif cat == 'tor_servicos':
                    resultados[cat] = _importar_tor(cats[cat], tor)
                elif cat == 'tox_servicos':
                    resultados[cat] = tox.importar_servicos(cats[cat])
                elif cat in ('dns_config', 'av_config'):
                    resultados[cat] = _importar_json(
                        os.path.join(dados_dir, f'{cat}.json'),
                        cats[cat],
                        _IGNORAR_NA_IMPORTACAO.get(cat, ())
                    )
            except Exception as e:
                logger.error(f"importar {cat}: {e}")
                resultados[cat] = {'sucesso': False, 'erro': str(e)}

        return {
            'sucesso':    True,
            'resultados': resultados,
            'mensagem':   f'{len(resultados)} categorias importadas!'
        }
    except json.JSONDecodeError:
        return {'sucesso': False, 'erro': 'JSON inválido'}
    except Exception as e:
        logger.error(f"importar_configuracoes: {e}")
        return {'sucesso': False, 'erro': str(e)}


def _importar_ufw(regras, firewall):
    ok = err = 0
    for r in regras:
        r = dict(r)
        r.pop('id', None)
        res = firewall.adicionar_regra(r, categoria='usuario',
                                       editavel=True)
        if res.get('sucesso'):
            ok += 1
        else:
            err += 1
    return {'sucesso': True,
            'mensagem': f'{ok} regras importadas, {err} erros'}


def _importar_tor(servicos, tor):
    ok = err = 0
    for s in servicos:
        interface = s.get('interface', 'localhost')
        ip_custom = '' if interface == 'localhost' \
            else s.get('ip_destino', '')
        res = tor.adicionar_servico(
            s.get('nome', ''), s.get('porta_virtual', 80),
            s.get('porta_destino', 80), interface, ip_custom
        )
        if res.get('sucesso'):
            ok += 1
        else:
            err += 1
    return {'sucesso': True,
            'mensagem': f'{ok} serviços importados, {err} erros'}


def _importar_json(path, dados, ignorar=()):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        existente = _ler_json(path, {}) or {}
        novos = {k: v for k, v in dados.items() if k not in ignorar}
        existente.update(novos)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(existente, f, indent=2, ensure_ascii=False)
        return {'sucesso': True, 'mensagem': 'Importado'}
    except Exception as e:
        logger.error(f"_importar_json {path}: {e}")
        return {'sucesso': False, 'erro': str(e)}
