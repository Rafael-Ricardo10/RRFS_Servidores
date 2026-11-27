#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=====================================================================
 GERADOR DE ÍCONE / LOGO - RRFS SERVIDORES v2.0
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
from PIL import Image, ImageDraw

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
COR_BORDA_TEAL  = (79, 209, 197, 128)    # teal com transparência


def _arredondado(draw, box, raio, fill=None, outline=None, largura=1):
    """Desenha retângulo com cantos arredondados."""
    draw.rounded_rectangle(box, radius=raio, fill=fill, outline=outline, width=largura)


def _linha_arredondada(draw, p1, p2, fill, largura):
    """Desenha linha com terminações redondas."""
    draw.line([p1, p2], fill=fill, width=largura)


def desenhar_logo(tam=512):
    """Desenha em alta resolução (com supersampling) e reduz no final,
    para ficar com bordas suaves."""
    escala = 4
    S = tam * escala
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    margem = int(S * 0.06)
    raio_fundo = int(S * 0.22)

    # ── Fundo principal com gradiente simulado ──
    # Retângulo base
    _arredondado(draw, [margem, margem, S - margem, S - margem], raio_fundo,
                 fill=COR_FUNDO)

    # Borda destacada (teal)
    _arredondado(draw, [margem, margem, S - margem, S - margem], raio_fundo,
                 outline=COR_DESTAQUE, largura=int(S * 0.016))

    # ── Rack de servidores: 3 unidades horizontais com design melhorado ──
    rack_x0 = int(S * 0.18)
    rack_x1 = int(S * 0.82)
    unidade_h = int(S * 0.12)
    espaco = int(S * 0.04)
    topo = int(S * 0.42)

    for i in range(3):
        y0 = topo + i * (unidade_h + espaco)
        y1 = y0 + unidade_h

        # Chassis da unidade (mais escuro)
        _arredondado(draw, [rack_x0, y0, rack_x1, y1], int(S * 0.028),
                     fill=COR_FUNDO_CARD, outline=COR_BORDA, largura=int(S * 0.008))

        # Destaque teal na borda esquerda (efeito 3D)
        _arredondado(draw, [rack_x0, y0, rack_x0 + int(S * 0.015), y1], int(S * 0.028),
                     fill=COR_DESTAQUE)

        # LED de status (verde aceso na unidade de cima, apagado nas outras)
        led_r = int(S * 0.020)
        led_cx = rack_x0 + int(S * 0.04)
        led_cy = (y0 + y1) // 2
        cor_led = COR_LED_VERDE if i == 0 else COR_LED_APAGADO

        # LED com brilho (círculo + sombra)
        draw.ellipse([led_cx - led_r - int(S * 0.005),
                      led_cy - led_r - int(S * 0.005),
                      led_cx + led_r + int(S * 0.005),
                      led_cy + led_r + int(S * 0.005)],
                     fill=tuple(list(cor_led[:3]) + [60]))  # sombra
        draw.ellipse([led_cx - led_r, led_cy - led_r, led_cx + led_r, led_cy + led_r],
                     fill=cor_led)

        # Ranhuras decorativas (slots do servidor) com design melhorado
        slot_y0 = (y0 + y1) // 2 - int(S * 0.008)
        slot_y1 = (y0 + y1) // 2 + int(S * 0.008)

        for j in range(3):
            lx0 = rack_x0 + int(S * 0.12) + j * int(S * 0.16)
            lx1 = lx0 + int(S * 0.08)

            # Ranhura com gradiente simulado
            _arredondado(draw, [lx0, slot_y0, lx1, slot_y1], int(S * 0.006),
                        fill=(40, 40, 40, 255), outline=COR_BORDA, largura=int(S * 0.004))

    # ── Ondas de sinal (acesso remoto) acima do rack - Design melhorado ──
    centro_x = S // 2
    centro_y = topo - int(S * 0.08)

    # Múltiplas camadas de ondas concêntricas (mais realista)
    for raio, largura, alpha in [
        (0.10, 0.018, 80),
        (0.16, 0.018, 120),
        (0.22, 0.018, 180),
        (0.28, 0.018, 100),
    ]:
        r = int(S * raio)
        bbox = [centro_x - r, centro_y - r, centro_x + r, centro_y + r]
        cor = COR_DESTAQUE[:3] + (alpha,)
        draw.arc(bbox, start=180, end=360, fill=cor, width=int(S * largura))

    # Ponto central do "satélite" emissor (maior e com glow)
    r_p = int(S * 0.032)

    # Glow externo
    for glow in range(int(S * 0.016), 0, -2):
        cor_glow = tuple(list(COR_DESTAQUE[:3]) + [max(0, 50 - glow * 2)])
        draw.ellipse([centro_x - r_p - glow, centro_y - int(r_p * 0.6) - glow,
                      centro_x + r_p + glow, centro_y + int(r_p * 1.4) + glow],
                     fill=cor_glow)

    # Ponto principal
    draw.ellipse([centro_x - r_p, centro_y - int(r_p * 0.6),
                  centro_x + r_p, centro_y + int(r_p * 1.4)],
                 fill=COR_DESTAQUE)

    # ── Efeito de vidro/cristal no centro ──
    # Pequeno destaque branco
    hl_r = int(r_p * 0.4)
    hl_x = centro_x - int(r_p * 0.3)
    hl_y = centro_y - int(r_p * 0.3)
    draw.ellipse([hl_x - hl_r, hl_y - hl_r, hl_x + hl_r, hl_y + hl_r],
                 fill=(255, 255, 255, 100))

    # ── Aplicar efeitos finais ──
    # (SEM filtros de suavização: o SMOOTH_MORE aplicado 2x borrava o ícone.
    #  O supersampling 4x + LANCZOS já dá bordas suaves e nítidas.)

    # Redimensionar com qualidade
    img = img.resize((tam, tam), Image.LANCZOS)
    return img


def desenhar_tray(tam=128):
    """Versão simplificada, de traços grossos, própria para a bandeja do
    sistema (onde o ícone aparece com ~22-32 px). Detalhes finos do logo
    completo viram borrão nesse tamanho."""
    escala = 8
    S = tam * escala
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    m = int(S * 0.04)
    d.rounded_rectangle([m, m, S - m, S - m], radius=int(S * 0.22),
                        fill=COR_FUNDO, outline=COR_DESTAQUE, width=int(S * 0.045))
    # 3 unidades de rack, grossas
    x0, x1 = int(S * 0.22), int(S * 0.78)
    h, esp, topo = int(S * 0.13), int(S * 0.05), int(S * 0.46)
    for i in range(3):
        y0 = topo + i * (h + esp)
        d.rounded_rectangle([x0, y0, x1, y0 + h], radius=int(S * 0.03),
                            fill=COR_FUNDO_CARD, outline=COR_DESTAQUE, width=int(S * 0.02))
        cy = y0 + h // 2
        r = int(S * 0.028)
        cx = x0 + int(S * 0.08)
        d.ellipse([cx - r, cy - r, cx + r, cy + r],
                  fill=COR_LED_VERDE if i == 0 else COR_LED_APAGADO)
    # ondas de sinal (opacas, grossas)
    cx, cy = S // 2, int(S * 0.40)
    for raio in (0.10, 0.19):
        r = int(S * raio)
        d.arc([cx - r, cy - r, cx + r, cy + r], start=200, end=340,
              fill=COR_DESTAQUE, width=int(S * 0.04))
    rp = int(S * 0.04)
    d.ellipse([cx - rp, cy - rp, cx + rp, cy + rp], fill=COR_DESTAQUE)
    return img.resize((tam, tam), Image.LANCZOS)


def gerar():
    """Gera todos os ícones necessários."""
    print("[*] Gerando logo em alta qualidade...")
    logo = desenhar_logo(512)

    # PNG 512x512 (cabeçalho do painel)
    caminho_png = STATIC_DIR / "logo.png"
    logo.save(caminho_png, "PNG")
    print(f"[✓] {caminho_png} (512x512)")

    # Ícone da bandeja (128x128, traços grossos, nítido)
    caminho_tray = STATIC_DIR / "tray.png"
    desenhar_tray(128).save(caminho_tray, "PNG")
    print(f"[✓] {caminho_tray} (128x128, bandeja)")

    # ICO multi-resolução (bandeja do sistema)
    caminho_ico = STATIC_DIR / "icone.ico"
    logo.save(caminho_ico, format="ICO",
              sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"[✓] {caminho_ico} (multi-resolução 16-256px)")

    # Favicon (páginas web)
    caminho_favicon = STATIC_DIR / "favicon.ico"
    logo.save(caminho_favicon, format="ICO", sizes=[(16, 16), (32, 32), (48, 48)])
    print(f"[✓] {caminho_favicon} (favicon 16-48px)")

    print("\n✅ Ícone/logo gerados com sucesso!")
    print(f"   - Logo: {caminho_png}")
    print(f"   - Ícone bandeja: {caminho_ico}")
    print(f"   - Favicon: {caminho_favicon}")


if __name__ == "__main__":
    try:
        gerar()
    except Exception as e:
        print(f"\n❌ Erro ao gerar ícone: {e}")
        import traceback
        traceback.print_exc()
