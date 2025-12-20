import json
import hashlib
import os
import shutil
from datetime import datetime, timedelta
import sys


def json_stringify_alphabetical(obj: dict):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def buf_to_bigint(buf: bytes):
    return int.from_bytes(buf, byteorder="little")


def bigint_to_buf(i: int):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder="little")


class RSA:
    def __init__(self):
        self.hexrays_modulus_bytes = bytes.fromhex(
            "edfd425cf978546e8911225884436c57140525650bcf6ebfe80edbc5fb1de68f4c66c29cb22eb668788afcb0abbb718044584b810f8970cddf227385f75d5dddd91d4f18937a08aa83b28c49d12dc92e7505bb38809e91bd0fbd2f2e6ab1d2e33c0c55d5bddd478ee8bf845fcef3c82b9d2929ecb71f4d1b3db96e3a8e7aaf93"
        )
        self.hexrays_modulus = buf_to_bigint(self.hexrays_modulus_bytes)

        self.patched_modulus_bytes = bytearray(self.hexrays_modulus_bytes)
        self.patched_modulus_bytes[17] ^= 1 << 4 
        self.patched_modulus = buf_to_bigint(self.patched_modulus_bytes)
        self.exponent = 0x13
        self.private_key = pow(self.exponent, -1, self.patched_modulus - 1)

    def decrypt(self, message: bytes):
        decrypted = pow(buf_to_bigint(message), self.exponent, self.patched_modulus)
        decrypted = bigint_to_buf(decrypted)
        return decrypted[::-1]

    def encrypt(self, message: bytes):
        encrypted = pow(
            buf_to_bigint(message[::-1]), self.private_key, self.patched_modulus
        )
        encrypted = bigint_to_buf(encrypted)
        return encrypted


def create_license():
    owner="hi@hex-rays.com"
    start_date = datetime.now().strftime("%Y-%m-%d")

    start_dt = datetime.strptime(start_date, "%Y-%m-%d")
    end_dt = start_dt + timedelta(days=10 * 365 - 1)
    end_date = end_dt.strftime("%Y-%m-%d")

    id = "48-2137-ACAB-69"
    license = {
        "header": {"version": 1},
        "payload": {
            "name": owner,
            "email": owner,
            "licenses": [
                {
                    "description": "IDA Expert-2",
                    "edition_id": "ida-pro",
                    "id": id,
                    "product_id": "IDAPRO",
                    "product_version": "9.1", 
                    "license_type": "named",
                    "seats": 1,
                    "start_date": start_date,
                    "end_date": end_date,
                    "issued_on": f"{start_date} 00:00:00",
                    "owner": "cracked",
                    "add_ons": get_addons(
                        owner=id,
                        start_date=start_date,
                        end_date=end_date,
                    ),
                    "features": [],
                }
            ],
        },
    }

    return license


def get_addons(owner: str, start_date: str, end_date: str) -> list[dict]:
    addons = [
        "HEXX86",
        "HEXX64",
        "HEXARM",
        "HEXARM64",
        "HEXMIPS",
        "HEXMIPS64",
        "HEXPPC",
        "HEXPPC64",
        "HEXRV",
        "HEXRV64",
        "HEXARC",
    ]

    result = []

    i = 0
    for addon in addons:
        i += 1
        result.append(
            {
                "id": f"48-1337-DEAD-{i:02}",
                "code": addon,
                "owner": owner,
                "start_date": start_date,
                "end_date": end_date,
            }
        )
    return result


def generate_license_file(license_data, filename="idapro.hexlic"):
    license_data["signature"] = sign_hexlic(license_data["payload"])
    serialized = json_stringify_alphabetical(license_data)

    with open(filename, "w") as f:
        f.write(serialized)

    print(f"Saved new license to {filename}!")
    return True


def patch_ida_files():
    files_to_patch = [
        "ida32.dll",
        "ida.dll",
        "libida32.so",
        "libida.so",
        "libida32.dylib",
        "libida.dylib",
    ]

    success_count = 0
    for filename in files_to_patch:
        if generate_patched_dll(filename):
            success_count += 1

    if sys.platform == "darwin":
        parent_path = os.path.abspath(os.curdir)
        if not parent_path.endswith("Contents/MacOS"):
            print(
                "Error: Unexpected path structure. In order to re-sign the bundle, this script should be run from xxx.app/Contents/MacOS/"
            )
            return success_count

        bundle_dir = os.path.abspath(os.path.join(parent_path, "../.."))

        try:
            result = os.system(f"xattr -c '{bundle_dir}'")
            if result != 0:
                print(
                    "Error: Failed to clear extended attributes on the IDA bundle."
                )
        except Exception as e:
            print(f"Error while trying to clear extended attributes: {e}")

        try:
            result = os.system(f"codesign --verbose -f -s - --deep '{bundle_dir}'")
            if result != 0:
                print("Error: Failed to re-sign the IDA bundle.")
        except Exception as e:
            print(f"Error while trying to re-sign the IDA bundle: {e}")

    return success_count


rsa = RSA()


def sign_hexlic(payload: dict) -> str:
    data = {"payload": payload}
    data_str = json_stringify_alphabetical(data)

    buffer = bytearray(128)

    for i in range(33):
        buffer[i] = 0x42

    sha256 = hashlib.sha256()
    sha256.update(data_str.encode())
    digest = sha256.digest()

    for i in range(32):
        buffer[33 + i] = digest[i]

    encrypted = rsa.encrypt(buffer)

    return encrypted.hex().upper()


def generate_patched_dll(filename):
    if not os.path.exists(filename):
        return False

    with open(filename, "rb") as f:
        data = f.read()

        if data.find(rsa.patched_modulus_bytes) != -1:
            print(f"{filename} looks to be already patched :)")
            return True

        if data.find(rsa.hexrays_modulus_bytes) == -1:
            print(f"{filename} doesn't contain the original modulus.")
            return False

        data = data.replace(
            rsa.hexrays_modulus_bytes, rsa.patched_modulus_bytes
        )

        patched_filename = f"{filename}.patched"
        with open(patched_filename, "wb") as f:
            f.write(data)

        print(f"Generated patch: {patched_filename}")

    try:
        with open(filename, "r+b"):
            pass
    except Exception:
        print(f"Error: {filename} is not writable. Cannot swap files.")
        return False

    backup_filename = f"{filename}.bak"
    try:
        if not os.path.exists(backup_filename):
            shutil.copy2(filename, backup_filename)
            print(f"Created backup: {backup_filename}")
        else:
            print(
                f"Backup already exists: {backup_filename}, skipping backup creation."
            )

        shutil.move(patched_filename, filename)
        print(f"Swapped {filename} with patched version")
        return True
    except Exception as e:
        print(f"Error swapping files: {e}")
        return False


def main():
    success = True

    success_count = patch_ida_files()
    success = success_count > 0

    if success_count == 0:
        print(
            "No files were patched. Ensure that you run this script from the IDA installation directory."
        )
        return 1

    print("Generating license...")
    license_data = create_license()

    success = generate_license_file(license_data)

    return 0 if success else 1


if __name__ == "__main__":
    exit(main())
