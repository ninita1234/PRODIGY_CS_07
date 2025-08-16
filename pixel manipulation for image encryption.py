#!/usr/bin/env python3
"""
Simple Image Encrypt/Decrypt via Pixel Manipulation

Methods:
  - xor:     XOR each pixel with key (0..255). Reversible with same key.
  - add:     Add key (0..255) modulo 256. Decrypt with same key (algorithm symmetric with modulo).
  - swaprb:  Swap Red and Blue channels. Self-inverse.
  - shuffle: Shuffle pixel order using a key-derived PRNG permutation. Decrypt with same key.

Usage examples:
  Encrypt with XOR:
    python image_cipher.py --mode encrypt --method xor --key 123 --input in.png --output out.png

  Decrypt with XOR:
    python image_cipher.py --mode decrypt --method xor --key 123 --input out.png --output restored.png

  Shuffle pixels:
    python image_cipher.py --mode encrypt --method shuffle --key "my passphrase" -i in.jpg -o enc.png
    python image_cipher.py --mode decrypt --method shuffle --key "my passphrase" -i enc.png -o dec.jpg

  Swap R/B channels (same for encrypt/decrypt):
    python image_cipher.py --mode encrypt --method swaprb -i in.png -o enc.png
    python image_cipher.py --mode decrypt --method swaprb -i enc.png -o dec.png
"""

import argparse
import hashlib
from typing import Tuple

import numpy as np
from PIL import Image


def load_image(path: str) -> Tuple[np.ndarray, str]:
    """
    Load an image as numpy array in a consistent mode.
    Preserve alpha channel if present.
    Returns (array, mode)
    """
    img = Image.open(path)
    # Normalize mode to either L, RGB, or RGBA to keep logic simple
    if img.mode in ("1", "L"):
        img = img.convert("L")
    elif img.mode in ("RGB", "RGBA"):
        pass
    else:
        # Convert other modes (e.g., P, CMYK) to RGBA to avoid data loss
        img = img.convert("RGBA")
    arr = np.array(img)
    return arr, img.mode


def save_image(arr: np.ndarray, mode: str, path: str) -> None:
    """
    Save numpy array back to image with provided mode.
    """
    img = Image.fromarray(arr.astype(np.uint8), mode=mode)
    img.save(path)


def key_to_int(key: str) -> int:
    """
    Derive a stable integer seed from an arbitrary string key.
    """
    h = hashlib.sha256(key.encode("utf-8")).digest()
    # Use 8 bytes to form a 64-bit integer seed
    return int.from_bytes(h[:8], "big", signed=False)


def apply_xor(arr: np.ndarray, k: int) -> np.ndarray:
    if not (0 <= k <= 255):
        raise ValueError("xor key must be in 0..255")
    return (arr.astype(np.uint16) ^ k).astype(np.uint8)


def apply_add(arr: np.ndarray, k: int) -> np.ndarray:
    if not (0 <= k <= 255):
        raise ValueError("add key must be in 0..255")
    return ((arr.astype(np.uint16) + k) % 256).astype(np.uint8)


def apply_swaprb(arr: np.ndarray) -> np.ndarray:
    # Works only if at least 3 channels (RGB or RGBA)
    if arr.ndim == 2:
        # Grayscale—nothing to swap; return as-is
        return arr
    if arr.shape[2] < 3:
        return arr
    out = arr.copy()
    out[..., 0], out[..., 2] = arr[..., 2], arr[..., 0]
    return out


def permute_pixels(arr: np.ndarray, seed: int, inverse: bool = False) -> np.ndarray:
    """
    Shuffle or unshuffle pixels consistently across channels using a PRNG seed.

    We treat the image as N pixels with C channels (C=1,3,4 etc).
    - For encrypt (inverse=False): arr_flat[perm]
    - For decrypt (inverse=True):  arr_flat[inv_perm]
    """
    # Flatten to (N, C)
    if arr.ndim == 2:
        h, w = arr.shape
        c = 1
        flat = arr.reshape(-1, 1)
    else:
        h, w, c = arr.shape
        flat = arr.reshape(-1, c)

    n = flat.shape[0]
    rng = np.random.default_rng(seed)
    perm = np.arange(n)
    rng.shuffle(perm)

    if inverse:
        # Build inverse permutation
        inv = np.empty_like(perm)
        inv[perm] = np.arange(n)
        out_flat = flat[inv]
    else:
        out_flat = flat[perm]

    if c == 1:
        return out_flat.reshape(h, w).astype(np.uint8)
    else:
        return out_flat.reshape(h, w, c).astype(np.uint8)


def process(
    mode: str,
    method: str,
    key: str,
    input_path: str,
    output_path: str,
) -> None:
    arr, mode_in = load_image(input_path)

    if method == "xor":
        if key is None:
            raise ValueError("xor requires --key (0..255).")
        try:
            k = int(key)
        except ValueError:
            raise ValueError("xor key must be an integer 0..255.")
        out = apply_xor(arr, k)

    elif method == "add":
        if key is None:
            raise ValueError("add requires --key (0..255).")
        try:
            k = int(key)
        except ValueError:
            raise ValueError("add key must be an integer 0..255.")
        # add is self-inverse mod 256: using the same operation restores the image
        out = apply_add(arr, k)

    elif method == "swaprb":
        # same operation for encrypt/decrypt
        out = apply_swaprb(arr)

    elif method == "shuffle":
        if key is None:
            raise ValueError("shuffle requires --key (string or int).")
        # derive seed from key (string/int both fine)
        seed = key_to_int(str(key))
        inverse = (mode.lower() == "decrypt")
        out = permute_pixels(arr, seed=seed, inverse=inverse)

    else:
        raise ValueError("Unknown method. Choose from: xor, add, swaprb, shuffle")

    save_image(out, mode_in, output_path)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Simple image encryption/decryption via pixel manipulation",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--mode",
        choices=["encrypt", "decrypt"],
        required=True,
        help="Operation mode",
    )
    p.add_argument(
        "--method",
        choices=["xor", "add", "swaprb", "shuffle"],
        required=True,
        help="Pixel manipulation method",
    )
    p.add_argument(
        "--key",
        type=str,
        default=None,
        help="Key (required for xor/add/shuffle). 0..255 for xor/add; any string for shuffle.",
    )
    p.add_argument(
        "-i", "--input",
        required=True,
        help="Input image path",
    )
    p.add_argument(
        "-o", "--output",
        required=True,
        help="Output image path",
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate key requirements
    if args.method in ("xor", "add", "shuffle") and args.key is None:
        parser.error(f"--key is required for method '{args.method}'")

    process(
        mode=args.mode,
        method=args.method,
        key=args.key,
        input_path=args.input,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
