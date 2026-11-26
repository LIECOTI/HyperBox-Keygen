import struct
import sys


def rotr(x: int, n: int) -> int:
    """32-bit right rotation."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def hyperbox_sha256(message: str) -> str:
    """Custom SHA-256 implementation matching Hyper Box v3.0.2 (type.jsc)."""
    # Truncated 30-element round constants array (K[17] is modified; K[18..51] are omitted)
    K = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEAD4A4FE, 0x391C0CB3, 0x4ED8AA4A,
        0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F,
        0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB,
        0xBEF9A3F7, 0xC67178F2,
    ]
    H = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ]

    data = [ord(c) for c in message]
    orig_len = len(data)
    data.append(0x80)
    while len(data) % 64 != 56:
        data.append(0)

    # Appends only 4 bytes (32-bit length) instead of 8 bytes
    data.extend(struct.pack(">I", (orig_len * 8) & 0xFFFFFFFF))

    for i in range(0, len(data), 64):
        chunk = data[i : i + 64]
        while len(chunk) < 64:
            chunk.append(0)

        w = [0] * 64
        for j in range(16):
            w[j] = (
                (chunk[j * 4] << 24)
                | (chunk[j * 4 + 1] << 16)
                | (chunk[j * 4 + 2] << 8)
                | chunk[j * 4 + 3]
            )
        for j in range(16, 64):
            s0 = rotr(w[j - 15], 7) ^ rotr(w[j - 15], 18) ^ (w[j - 15] >> 3)
            s1 = rotr(w[j - 2], 17) ^ rotr(w[j - 2], 19) ^ (w[j - 2] >> 10)
            w[j] = (w[j - 16] + s0 + w[j - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = H
        for j in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g)
            if j < len(K):
                temp1 = (h + S1 + ch + K[j] + w[j]) & 0xFFFFFFFF
            else:
                # K[j] is undefined in JS, so (.. + undefined + ..) >>> 0 == 0
                temp1 = 0
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF

        H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

    return "".join(f"{x:08x}" for x in H)


def convert_to_odd_numbers(hex_tail: str) -> str:
    """Convert each hex digit to an odd decimal number and take the first 6 digits."""
    result = ""
    for ch in hex_tail:
        digit = int(ch, 16)
        if digit % 2 == 0:
            digit += 1
        result += str(digit)
    return result[:6]


def get_unlock_code(ccode: str) -> str:
    """Calculate the 6-digit activation code from the 8-digit device ccode."""
    unlock_text = f"{ccode}/data/app/watchface/market/c4h2h1DBaGO//_lua/app/"
    digest = hyperbox_sha256(unlock_text)
    return convert_to_odd_numbers(digest[-6:])


def main() -> None:
    if len(sys.argv) > 1:
        ccode = sys.argv[1].strip()
    else:
        ccode = input("Enter 8-digit device code (ccode): ").strip()

    if len(ccode) != 8 or not ccode.isdigit():
        print("Error: ccode must be an 8-digit number.")
        sys.exit(1)

    code = get_unlock_code(ccode)
    print(f"Activation code: {code}")


if __name__ == "__main__":
    main()
