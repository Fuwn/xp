#!/usr/bin/env python3

import argparse
import hashlib
import json
import os
import re
from concurrent.futures import ProcessPoolExecutor

from umskt.umskt import add_points, decode_pkey, scalar_mult

VALID_CHARACTERS = set("BCDFGHJKMPQRTVWXY2346789")
KEY_FORMAT = re.compile(
    r"^[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}$"
)
XP_BINKS = [
    "2E",  # XP Pro VLK
    "2C",  # XP Pro Retail
    "2D",  # XP Pro OEM
    "2A",  # XP Home Retail
    "2B",  # XP Home OEM
    "64",  # XP Pro 64-bit VLK
    "66",  # XP Pro 64-bit
    "65",  # XP Pro 64-bit VLK OEM
    "67",  # XP Pro 64-bit OEM
]
BINK_NAMES = {
    "2E": "XP Pro VLK",
    "2C": "XP Pro Retail",
    "2D": "XP Pro OEM",
    "2A": "XP Home Retail",
    "2B": "XP Home OEM",
    "64": "XP Pro 64-bit VLK",
    "66": "XP Pro 64-bit",
    "65": "XP Pro 64-bit VLK OEM",
    "67": "XP Pro 64-bit OEM",
}


def int_to_bytes(value, length):
    return value.to_bytes(length, byteorder="little")


def load_bink_data(keysfile):
    with open(keysfile) as file:
        return json.load(file)


def verify_key(raw_product_key, bink_data):
    prime = int(bink_data["p"])
    curve_a = int(bink_data["a"])
    generator = (int(bink_data["g"]["x"]), int(bink_data["g"]["y"]))
    public_key = (int(bink_data["pub"]["x"]), int(bink_data["pub"]["y"]))
    coordinate_length = (prime.bit_length() + 7) // 8
    product_id = (raw_product_key & 0x7FFFFFFF) >> 1
    hash_value = (raw_product_key >> 31) & 0xFFFFFFF
    signature = raw_product_key >> 59

    if signature == 0:
        return False

    # verification_point = (signature * generator) + (hash_value * public_key)
    signature_component = scalar_mult(signature, generator, prime, curve_a)
    hash_component = scalar_mult(hash_value, public_key, prime, curve_a)
    verification_point = add_points(signature_component, hash_component, prime, curve_a)

    if verification_point is None:
        return False

    point_x, point_y = verification_point
    digest = hashlib.sha1(
        int_to_bytes(product_id << 1, 4)
        + int_to_bytes(point_x, coordinate_length)
        + int_to_bytes(point_y, coordinate_length)
    ).digest()
    computed_hash = int.from_bytes(digest[:4], byteorder="little") >> 4
    computed_hash &= 0xFFFFFFF

    return hash_value == computed_hash


def verify_key_against_all_binks(entry, bink_database):
    key = entry["key"]

    if not KEY_FORMAT.match(key):
        entry["reason"] = "malformed format"

        return "invalid_format", entry

    stripped_key = key.replace("-", "")
    invalid_chars = sorted(set(stripped_key) - VALID_CHARACTERS)

    if invalid_chars:
        entry["reason"] = f"invalid character(s): {', '.join(invalid_chars)}"

        return "invalid_format", entry

    raw_product_key = decode_pkey(key)

    for bink_id in XP_BINKS:
        if bink_id not in bink_database["BINK"]:
            continue

        if verify_key(raw_product_key, bink_database["BINK"][bink_id]):
            entry["bink"] = f"{bink_id} ({BINK_NAMES[bink_id]})"

            return "valid", entry

    entry["reason"] = "ECDSA signature verification failed"

    return "invalid_signature", entry


def validate_keys(keys_file="keys.json"):
    script_directory = os.path.dirname(os.path.abspath(__file__))
    bink_file = os.path.join(script_directory, "umskt", "umskt", "keys.json")
    bink_database = load_bink_data(bink_file)

    with open(keys_file, "r") as file:
        data = json.load(file)

    entries = []

    for edition in data["editions"].values():
        for category in edition["categories"].values():
            for key in category["keys"]:
                entries.append(
                    {
                        "key": key,
                        "edition": edition["name"],
                        "category": category["name"],
                    }
                )

    results = {"valid": [], "invalid_format": [], "invalid_signature": []}

    with ProcessPoolExecutor() as executor:
        futures = [
            executor.submit(verify_key_against_all_binks, entry, bink_database)
            for entry in entries
        ]

        for future in futures:
            category, entry = future.result()

            results[category].append(entry)

    return results


def generate_report(results):
    total = (
        len(results["valid"])
        + len(results["invalid_format"])
        + len(results["invalid_signature"])
    )
    lines = []

    lines.append("# Summary\n")
    lines.append(f"- Validated: {total}")
    lines.append(f"- Valid: {len(results['valid'])}")
    lines.append(f"- Invalid format: {len(results['invalid_format'])}")
    lines.append(f"- Invalid signature: {len(results['invalid_signature'])}")

    if results["valid"]:
        lines.append(f"\n## Valid ({len(results['valid'])})\n")

        for entry in results["valid"]:
            lines.append(f"- {entry['key']} ({entry['bink']})")

    if results["invalid_format"]:
        lines.append(f"\n## Invalid format ({len(results['invalid_format'])})\n")

        for entry in results["invalid_format"]:
            lines.append(f"- {entry['key']} ({entry['reason']})")

    if results["invalid_signature"]:
        lines.append(f"\n## Invalid signature ({len(results['invalid_signature'])})\n")

        for entry in results["invalid_signature"]:
            lines.append(f"- {entry['key']} ({entry['edition']} / {entry['category']})")

    return "\n".join(lines) + "\n"


def remove_invalid_keys(keys_file, results):
    invalid_keys = {entry["key"] for entry in results["invalid_format"]} | {
        entry["key"] for entry in results["invalid_signature"]
    }

    with open(keys_file, "r") as file:
        data = json.load(file)

    removed = 0

    for edition in data["editions"].values():
        for category in edition["categories"].values():
            original_count = len(category["keys"])
            category["keys"] = [
                key for key in category["keys"] if key not in invalid_keys
            ]
            removed += original_count - len(category["keys"])

    with open(keys_file, "w") as file:
        json.dump(data, file, indent=2, ensure_ascii=False)
        file.write("\n")

    return removed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate Windows XP product keys")

    parser.add_argument(
        "--clean",
        action="store_true",
        help="remove invalid keys from keys.json",
    )

    arguments = parser.parse_args()
    results = validate_keys()
    report = generate_report(results)

    with open("report.md", "w") as file:
        file.write(report)

    print("Generated report.md")

    if arguments.clean:
        removed = remove_invalid_keys("keys.json", results)

        print(f"Removed {removed} invalid keys from keys.json")
