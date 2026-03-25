"""
PhishGuard – Icon Generator
Run this script once to generate PNG icons for the extension.
Requires: pip install Pillow
"""

import os
import math

try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PILLOW = True
except ImportError:
    HAS_PILLOW = False

def draw_shield(size):
    """Draw a shield icon with a fish symbol crossed out."""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = max(1, size // 10)
    cx, cy = size // 2, size // 2

    # Shield background gradient simulation (flat color)
    # Outer shield
    shield_points = _shield_polygon(size, pad)
    draw.polygon(shield_points, fill=(14, 30, 62, 255))   # dark blue

    # Inner shield (lighter border effect)
    inner_pad = max(2, size // 8)
    inner_shield = _shield_polygon(size, inner_pad + pad // 2)
    draw.polygon(inner_shield, outline=(96, 165, 250, 200), width=max(1, size // 20))

    # Draw a stylized "P" or shield emblem in the center
    icon_color = (52, 211, 153, 255)  # emerald green
    warn_color = (239, 68, 68, 255)   # red

    # Draw exclamation mark '!'
    bar_w = max(2, size // 8)
    bar_h = max(3, size // 3)
    bar_x = cx - bar_w // 2
    bar_y = cy - size // 3

    # Stem
    draw.rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + bar_h - bar_w], fill=warn_color)
    # Dot
    dot_y = bar_y + bar_h
    dot_r = bar_w
    draw.ellipse([bar_x - dot_r // 4, dot_y, bar_x + bar_w + dot_r // 4, dot_y + bar_w + dot_r // 2], fill=warn_color)

    return img


def _shield_polygon(size, pad):
    """Generate shield-shaped polygon points."""
    w, h = size - pad * 2, size - pad * 2
    ox, oy = pad, pad
    mid_x = ox + w // 2

    points = [
        (ox, oy),
        (ox + w, oy),
        (ox + w, oy + int(h * 0.6)),
        (mid_x, oy + h),
        (ox, oy + int(h * 0.6)),
    ]
    return points


def generate_icons_pillow():
    os.makedirs('icons', exist_ok=True)
    for size in [16, 32, 48, 128]:
        img = draw_shield(size)
        path = f'icons/icon{size}.png'
        img.save(path, 'PNG')
        print(f'  Created {path}')


def generate_icons_fallback():
    """Generate minimal valid 1x1 PNG files as a last resort."""
    import struct, zlib

    def minimal_png(size, r, g, b):
        def chunk(name, data):
            c = zlib.crc32(name + data) & 0xffffffff
            return struct.pack('>I', len(data)) + name + data + struct.pack('>I', c)

        ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
        raw = b''
        for _ in range(size):
            row = b'\x00' + bytes([r, g, b] * size)
            raw += row
        idat = zlib.compress(raw)

        return (b'\x89PNG\r\n\x1a\n'
                + chunk(b'IHDR', ihdr)
                + chunk(b'IDAT', idat)
                + chunk(b'IEND', b''))

    os.makedirs('icons', exist_ok=True)
    for size in [16, 32, 48, 128]:
        path = f'icons/icon{size}.png'
        with open(path, 'wb') as f:
            f.write(minimal_png(size, 14, 30, 62))  # dark blue
        print(f'  Created {path} (fallback solid color)')


if __name__ == '__main__':
    print('PhishGuard Icon Generator')
    print('=========================')
    if HAS_PILLOW:
        print('Using Pillow to generate shield icons...')
        generate_icons_pillow()
    else:
        print('Pillow not found. Generating minimal PNG placeholders...')
        print('Install Pillow for full icons: pip install Pillow')
        generate_icons_fallback()
    print('Done.')
