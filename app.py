import argparse
import base64
import getpass
import os
import sys
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

VERSIE = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # 256 bits

@dataclass(frozen=True)
class Envelop:
    versie: int
    salt: bytes
    nonce: bytes
    ciphertext: bytes  # bevat GCM-tag

    def to_bytes(self) -> bytes:
        return bytes([self.versie]) + self.salt + self.nonce + self.ciphertext

    @staticmethod
    def from_bytes(blob: bytes) -> "Envelop":
        if len(blob) < 1 + SALT_LEN + NONCE_LEN + 16:
            raise ValueError("Inhoud is te kort of beschadigd")
        v = blob[0]
        if v != VERSIE:
            raise ValueError(f"Onbekende versie: {v}")
        off = 1
        salt = blob[off:off + SALT_LEN]; off += SALT_LEN
        nonce = blob[off:off + NONCE_LEN]; off += NONCE_LEN
        ct = blob[off:]
        return Envelop(v, salt, nonce, ct)

def _derive_key_from_pass(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=2**14, r=8, p=1)
    return kdf.derive(passphrase.encode('utf-8'))

def _read_keyfile(path: str) -> bytes:
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != KEY_LEN:
        raise ValueError("Keyfile moet exact 32 bytes (256-bit) zijn.")
    return key

def generate_keyfile(path: str) -> None:
    if os.path.exists(path):
        raise FileExistsError("Bestand bestaat al: " + path)
    key = os.urandom(KEY_LEN)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def encrypt_bytes(data: bytes, passphrase: Optional[str], keyfile: Optional[str]) -> bytes:
    if not data:
        raise ValueError("Geen data om te versleutelen")
    if (passphrase is None) == (keyfile is None):
        raise ValueError("Geef óf een wachtzin óf een keyfile (niet beide).")
    salt = os.urandom(SALT_LEN)
    key = _read_keyfile(keyfile) if keyfile else _derive_key_from_pass(passphrase, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)
    env = Envelop(VERSIE, salt, nonce, ct)
    return env.to_bytes()

def decrypt_bytes(blob: bytes, passphrase: Optional[str], keyfile: Optional[str]) -> bytes:
    if (passphrase is None) == (keyfile is None):
        raise ValueError("Geef óf een wachtzin óf een keyfile (niet beide).")
    env = Envelop.from_bytes(blob)
    key = _read_keyfile(keyfile) if keyfile else _derive_key_from_pass(passphrase, env.salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(env.nonce, env.ciphertext, associated_data=None)

def encrypt_text_to_b64(text: str, passphrase: Optional[str], keyfile: Optional[str]) -> str:
    if text is None or text == "":
        raise ValueError("Geen tekst om te versleutelen")
    data = text.encode("utf-8")
    return base64.b64encode(encrypt_bytes(data, passphrase, keyfile)).decode('ascii')

def decrypt_text_from_b64(b64: str, passphrase: Optional[str], keyfile: Optional[str]) -> str:
    if b64 is None or b64 == "":
        raise ValueError("Geen Base64-tekst om te ontsleutelen")
    blob = base64.b64decode(b64.encode('ascii'))
    pt = decrypt_bytes(blob, passphrase, keyfile)
    return pt.decode('utf-8')

def _get_passphrase_from_args(args) -> Optional[str]:
    if args.keyfile:
        return None
    if args.passphrase_env:
        v = os.getenv(args.passphrase_env)
        if v is None:
            print(f"Omgevingsvariabele {args.passphrase_env} is niet gezet", file=sys.stderr)
            sys.exit(1)
        return 
    return getpass.getpass("Wachtzin: ")

def cmd_generate_key(args):
    try:
        generate_keyfile(args.out)
        print("Keyfile geschreven naar", args.out)
    except Exception as e:
        print("Fout bij keyfile genereren:", e, file=sys.stderr)
        sys.exit(1)

def cmd_encrypt(args):
    passphrase = _get_passphrase_from_args(args)
    try:
        if args.text is not None:
            out = encrypt_text_to_b64(args.text, passphrase, args.keyfile)
            print(out)
            return

        if not args.infile:
            print("Geef --text of --infile op", file=sys.stderr)
            sys.exit(1)

        with open(args.infile, "rb") as f:
            data = f.read()
        if not data:
            print("Inputbestand is leeg", file=sys.stderr)
            sys.exit(1)

        blob = encrypt_bytes(data, passphrase, args.keyfile)
        if args.outfile:
            with open(args.outfile, "wb") as f:
                f.write(blob)
            print("Geschreven:", args.outfile)
        else:
            sys.stdout.buffer.write(blob)

    except Exception as e:
        print("Encryptie mislukt:", e, file=sys.stderr)
        sys.exit(1)

def cmd_decrypt(args):
    passphrase = _get_passphrase_from_args(args)
    try:
        if args.text is not None:
            try:
                out = decrypt_text_from_b64(args.text, passphrase, args.keyfile)
                print(out)
            except Exception as e:
                print("Ontsleutelen mislukt:", e, file=sys.stderr)
                sys.exit(1)
            return

        if not args.infile:
            print("Geef --text of --infile op", file=sys.stderr)
            sys.exit(1)

        with open(args.infile, "rb") as f:
            blob = f.read()
        if not blob:
            print("Inputbestand is leeg", file=sys.stderr)
            sys.exit(1)

        data = decrypt_bytes(blob, passphrase, args.keyfile)
        if args.outfile:
            with open(args.outfile, "wb") as f:
                f.write(data)
            print("Geschreven:", args.outfile)
        else:
            sys.stdout.buffer.write(data)

    except Exception as e:
        print("Decryptie mislukt:", e, file=sys.stderr)
        sys.exit(1)

def build_parser():
    p = argparse.ArgumentParser(description="Kleine encrypt/decrypt tool (AES-256-GCM)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--text", help="Tekst (encrypt: plaintext, decrypt: Base64)")
        sp.add_argument("--infile", help="Pad naar inputbestand")
        sp.add_argument("--outfile", help="Pad naar outputbestand")
        sp.add_argument("--keyfile", help="Gebruik 32-byte keyfile")
        sp.add_argument("--passphrase-env", help="Lees wachtzin uit omgevingsvariabele")

    p_enc = sub.add_parser("encrypt", help="Versleutel tekst of bestand")
    add_common(p_enc)
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Ontsleutel tekst of bestand")
    add_common(p_dec)
    p_dec.set_defaults(func=cmd_decrypt)

    p_gen = sub.add_parser("generate-key", help="Genereer 32-byte keyfile")
    p_gen.add_argument("--out", required=True, help="Pad naar keyfile")
    p_gen.set_defaults(func=cmd_generate_key)

    return p

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

if __name__ == "__main__":
    main()
