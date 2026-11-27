#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 GERADOR DE ÍCONE / LOGO - RRFS SERVIDORES
=====================================================================
Desenha (sem depender de imagens externas) o logotipo do sistema:
um rack de servidores estilizado com ondas de sinal acima (alusão
a "acesso remoto"), nas cores do painel (fundo escuro + teal).

Gera em static/:
  - logo.png     (512x512 - usado no cabeçalho do HTML)
  - icone.ico    (multi-resolução - usado na bandeja do sistema)
  - favicon.ico  (16/32/48 - usado como favicon das páginas)

Uso:
  python gerar_icone.py
"""

from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

# Paleta de cores (igual ao tema do painel web)
COR_FUNDO       = (18, 18, 18, 255)      # #121212
COR_FUNDO_CARD  = (30, 30, 30, 255)      # #1e1e1e
COR_BORDA       = (60, 60, 60, 255)      # #333/#3c3c3c
COR_DESTAQUE    = (79, 209, 197, 255)    # #4fd1c5 (teal)
COR_LED_VERDE   = (107, 255, 176, 255)   # #6bffb0
COR_LED_APAGADO = (75, 75, 75, 255)


def _arredondado(draw, box, raio, fill=None, outline=None, largura=1):
    draw.rounded_rectangle(box, radius=raio, fill=fill, outline=outline, width=largura)


def desenhar_logo(tam=512):
    """Desenha em alta resolução (com supersampling) e reduz no final,
    para ficar com bordas suaves."""
    escala = 4
    S = tam * escala
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    margem = int(S * 0.06)
    raio_fundo = int(S * 0.22)

    # Fundo arredondado com borda destacada
    _arredondado(draw, [margem, margem, S - margem, S - margem], raio_fundo,
                 fill=COR_FUNDO)
    _arredondado(draw, [margem, margem, S - margem, S - margem], raio_fundo,
                 outline=COR_DESTAQUE, largura=int(S * 0.014))

    # ── Rack de servidores: 3 unidades horizontais ──
    rack_x0 = int(S * 0.20)
    rack_x1 = int(S * 0.80)
    unidade_h = int(S * 0.115)
    espaco = int(S * 0.045)
    topo = int(S * 0.44)

    for i in range(3):
        y0 = topo + i * (unidade_h + espaco)
        y1 = y0 + unidade_h
        _arredondado(draw, [rack_x0, y0, rack_x1, y1], int(S * 0.025),
                     fill=COR_FUNDO_CARD, outline=COR_BORDA, largura=int(S * 0.007))
        # LED de status (verde aceso na unidade de cima, apagado nas outras)
        led_r = int(S * 0.018)
        led_cx = rack_x0 + int(S * 0.035)
        led_cy = (y0 + y1) // 2
        cor_led = COR_LED_VERDE if i == 0 else COR_LED_APAGADO
        draw.ellipse([led_cx - led_r, led_cy - led_r, led_cx + led_r, led_cy + led_r],
                     fill=cor_led)
        # ranhuras decorativas (slots do servidor)
        for j in range(3):
            lx0 = rack_x0 + int(S * 0.10) + j * int(S * 0.14)
            lx1 = lx0 + int(S * 0.09)
            ly = (y0 + y1) // 2
            draw.line([lx0, ly, lx1, ly], fill=COR_BORDA, width=int(S * 0.009))

    # ── Ondas de sinal (acesso remoto) acima do rack ──
    centro_x = S // 2
    centro_y = topo - int(S * 0.02)
    for raio, largura, alpha in [(0.12, 0.020, 255), (0.17, 0.017, 190), (0.22, 0.014, 130)]:
        r = int(S * raio)
        bbox = [centro_x - r, centro_y - r, centro_x + r, centro_y]
        cor = COR_DESTAQUE[:3] + (alpha,)
        draw.arc(bbox, start=200, end=340, fill=cor, width=int(S * largura))

    # ponto central do "satélite" emissor
    r_p = int(S * 0.026)
    draw.ellipse([centro_x - r_p, centro_y - int(r_p * 0.6),
                  centro_x + r_p, centro_y + int(r_p * 1.4)],
                 fill=COR_DESTAQUE)

    img = img.filter(ImageFilter.SMOOTH_MORE)
    img = img.resize((tam, tam), Image.LANCZOS)
    return img


def gerar():
    logo = desenhar_logo(512)

    caminho_png = STATIC_DIR / "logo.png"
    logo.save(caminho_png, "PNG")
    print(f"[OK] {caminho_png}")

    caminho_ico = STATIC_DIR / "icone.ico"
    logo.save(caminho_ico, format="ICO",
              sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"[OK] {caminho_ico}")

    caminho_favicon = STATIC_DIR / "favicon.ico"
    logo.save(caminho_favicon, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    print(f"[OK] {caminho_favicon}")

    print("Ícone/logo gerados com sucesso.")


if __name__ == "__main__":
    gerar()
