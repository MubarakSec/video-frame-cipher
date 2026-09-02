#!/usr/bin/env python3
"""Generate deterministic, implementation-backed data for the VFC explainer.

The Remotion film should never invent cipher states, keys, payload bytes, or
audio measurements.  This script imports the real VFC v0.2 modules and emits a
TypeScript fixture containing one small, reproducible end-to-end trace.

It intentionally uses fixed demo credentials, salt, and IV.  They are public
teaching vectors, not values that should be copied into normal encryption.
"""

from __future__ import annotations

import argparse
import array
import hashlib
import json
import math
import random
import statistics
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT))

from vfc import cipher  # noqa: E402
from vfc import core  # noqa: E402
from vfc import fingerprint  # noqa: E402
from vfc import keys  # noqa: E402
from vfc import payload  # noqa: E402
from vfc import prng  # noqa: E402
from vfc import stego  # noqa: E402


DEFAULT_OUTPUT = Path(
    "/home/mobta/tools/remotion/src/projects/vfc_deep_dive/vfc-trace-data.ts"
)

PASSWORD = b"BlackRing-2028"
FRAME_NO = 30
SALT = bytes.fromhex("00112233445566778899aabbccddeeff")
IV = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
FILENAME = "demo.txt"
SECRET = b"VFC secret"


def source_frame() -> list[list[int]]:
    """The exact deterministic 64x64 carrier fixture used by vfc/tests.py."""
    return [
        [
            (
                128
                + int(60 * math.sin(x / 6.0) + 60 * math.sin(y / 7.0))
            )
            % 256
            for x in range(64)
        ]
        for y in range(64)
    ]


def state_record(state: list[list[int]]) -> dict:
    """Represent a column-major cipher state without hiding its 4x4 layout."""
    return {
        "bytesHex": cipher._from_state(state).hex(),
        "gridHex": [[f"{value:02x}" for value in row] for row in state],
        "gridDecimal": state,
    }


def byte_diff(left: bytes, right: bytes) -> dict:
    xor = bytes(a ^ b for a, b in zip(left, right))
    changed_indices = [i for i, value in enumerate(xor) if value]
    return {
        "changedByteIndices": changed_indices,
        "changedBytes": len(changed_indices),
        "changedBits": sum(value.bit_count() for value in xor),
        "xorHex": xor.hex(),
    }


def trace_block(block: bytes, round_keys: list[bytes]) -> dict:
    """Capture every real SPN layer, preserving the implementation order."""
    input_state = cipher._to_state(block)
    state = cipher._add_round_key(input_state, round_keys[0])
    rounds = []
    for number in range(1, cipher.ROUNDS + 1):
        sub_bytes = cipher._sub_bytes(state, cipher.SBOX)
        shift_rows = cipher._shift_rows(sub_bytes)
        mix_columns = cipher._mix_columns(shift_rows, cipher.MDS)
        add_round_key = cipher._add_round_key(mix_columns, round_keys[number])
        rounds.append(
            {
                "round": number,
                "subBytes": state_record(sub_bytes),
                "shiftRows": state_record(shift_rows),
                "mixColumns": state_record(mix_columns),
                "addRoundKey": state_record(add_round_key),
            }
        )
        state = add_round_key

    output = cipher._from_state(state)
    assert output == cipher.encrypt_block(block, round_keys)
    return {
        "input": state_record(input_state),
        "initialWhitening": state_record(
            cipher._add_round_key(input_state, round_keys[0])
        ),
        "rounds": rounds,
        "output": state_record(state),
    }


def fingerprint_trace() -> tuple[dict, bytes]:
    gray = source_frame()
    normalized = fingerprint._nearest_resize(
        gray, fingerprint.GRID, fingerprint.GRID
    )
    step = fingerprint.GRID // fingerprint.BLOCKS
    averages_flat = []
    for block_y in range(fingerprint.BLOCKS):
        for block_x in range(fingerprint.BLOCKS):
            values = [
                normalized[y][x]
                for y in range(block_y * step, block_y * step + step)
                for x in range(block_x * step, block_x * step + step)
            ]
            averages_flat.append(sum(values) / len(values))

    median = statistics.median(averages_flat)
    bits = [1 if average >= median else 0 for average in averages_flat]
    packed = bytearray(8)
    for index, bit in enumerate(bits):
        if bit:
            packed[index // 8] |= 1 << (7 - index % 8)

    actual = fingerprint.fingerprint_from_gray(gray)
    assert bytes(packed) == actual
    return (
        {
            "fixture": "The deterministic 64x64 sinusoidal frame from vfc/tests.py",
            "sourceShape": [64, 64],
            "resizeMethod": "nearest-neighbour",
            "normalizedShape": [32, 32],
            "normalizedPixels": normalized,
            "blockLayout": [8, 8],
            "pixelsPerBlock": [4, 4],
            "blockAverages": [
                averages_flat[row * 8 : (row + 1) * 8] for row in range(8)
            ],
            "median": median,
            "thresholdRule": "1 when blockAverage >= median; otherwise 0",
            "bits": [bits[row * 8 : (row + 1) * 8] for row in range(8)],
            "bitString": "".join(str(bit) for bit in bits),
            "bytesHex": actual.hex(),
        },
        actual,
    )


def kdf_record(
    *,
    purpose: str,
    label: bytes,
    fingerprint_bytes: bytes,
    salt: bytes,
    output: bytes,
) -> dict:
    frame_bytes = FRAME_NO.to_bytes(4, "big")
    pbkdf2_salt = label + fingerprint_bytes + frame_bytes + salt
    parts = [
        {"name": "domain label", "ascii": label.decode("ascii"), "hex": label.hex()},
        {"name": "fingerprint", "hex": fingerprint_bytes.hex()},
        {"name": "frame_no (BE32)", "value": FRAME_NO, "hex": frame_bytes.hex()},
    ]
    if salt:
        parts.append({"name": "random salt", "hex": salt.hex()})
    return {
        "purpose": purpose,
        "primitive": "PBKDF2-HMAC-SHA256",
        "iterations": keys.PBKDF2_ITERATIONS,
        "derivedKeyBytes": 32,
        "passwordAscii": PASSWORD.decode("ascii"),
        "passwordHex": PASSWORD.hex(),
        "pbkdf2SaltPartsInExactOrder": parts,
        "pbkdf2SaltHex": pbkdf2_salt.hex(),
        "outputHex": output.hex(),
    }


def deterministic_audio_samples(count: int = 48_000) -> array.array:
    """One second of the deterministic synthetic PCM carrier used in tests."""
    return array.array(
        "h", (((0x9E37 * index) % 36_000 - 18_000) for index in range(count))
    )


def source_hashes() -> dict[str, str]:
    paths = (
        "vfc/fingerprint.py",
        "vfc/keys.py",
        "vfc/cipher.py",
        "vfc/payload.py",
        "vfc/prng.py",
        "vfc/stego.py",
        "vfc/core.py",
    )
    return {
        path: hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest()
        for path in paths
    }


def run_actual_test_suite() -> dict:
    """Run the exported 13 checks from ``vfc/tests.py`` in their real order.

    The suite owns one module-level deterministic RNG and intentionally shares
    it across checks.  Resetting it here reproduces a fresh invocation of
    ``python3 -m vfc.tests`` even when this generator is imported more than
    once in the same Python process.  Encryption tests still use ``os.urandom``
    for salt/IV, as the production core does, but every check's pass/fail
    property is deterministic and independent of those public random values.
    """
    from vfc import tests as test_module

    test_module.rng = random.Random("VFC-tests-0.2")
    results = []
    for index, (label, check) in enumerate(test_module.CHECKS, start=1):
        error = None
        try:
            passed = bool(check())
        except Exception as exception:  # noqa: BLE001 - mirror suite reporting
            passed = False
            error = f"{type(exception).__name__}: {exception}"
        result = {"index": index, "label": label, "passed": passed}
        if error is not None:
            result["error"] = error
        results.append(result)

    passed_count = sum(result["passed"] for result in results)
    return {
        "source": "vfc/tests.py CHECKS, executed in declared order",
        "rngSeed": "VFC-tests-0.2",
        "count": len(results),
        "passedCount": passed_count,
        "failedCount": len(results) - passed_count,
        "allPassed": passed_count == len(results),
        "results": results,
    }


def build_trace() -> dict:
    test_suite = run_actual_test_suite()
    assert test_suite["count"] == 13
    assert test_suite["allPassed"]

    fp_trace, fp = fingerprint_trace()

    k_embed = keys.derive_k_embed(PASSWORD, fp, FRAME_NO)
    k_enc, k_auth = keys.derive_enc_auth(PASSWORD, fp, FRAME_NO, SALT)
    round_keys = keys.expand_round_keys(k_enc, cipher.ROUNDS)

    inner_plaintext = core._pack_plaintext(FILENAME, SECRET, compress=False)
    padded = cipher.pkcs7_pad(inner_plaintext, 16)
    assert len(padded) == 32
    p1, p2 = padded[:16], padded[16:]
    x1 = cipher._xor(p1, IV)
    c1 = cipher.encrypt_block(x1, round_keys)
    x2 = cipher._xor(p2, c1)
    c2 = cipher.encrypt_block(x2, round_keys)
    ciphertext = c1 + c2
    assert ciphertext == cipher.cbc_encrypt(inner_plaintext, round_keys, IV)
    assert cipher.cbc_decrypt(ciphertext, round_keys, IV) == inner_plaintext

    block_trace = trace_block(x1, round_keys)
    assert block_trace["output"]["bytesHex"] == c1.hex()

    full_payload = payload.build(
        k_embed, k_auth, SALT, IV, FRAME_NO, ciphertext
    )
    parsed_header = payload.read_header(full_payload[: payload.HEADER_LEN])
    assert parsed_header == {
        "magic": keys.compute_magic(k_embed),
        "version": payload.VERSION,
        "flags": 0,
        "salt": SALT,
        "iv": IV,
        "frame_no": FRAME_NO,
        "ct_len": len(ciphertext),
    }
    assert payload.verify_and_split(full_payload, k_auth) == ciphertext

    tampered = bytearray(full_payload)
    tampered[payload.HEADER_LEN + 3] ^= 1
    tamper_rejected = False
    try:
        payload.verify_and_split(bytes(tampered), k_auth)
    except ValueError:
        tamper_rejected = True
    assert tamper_rejected

    original_samples = deterministic_audio_samples()
    original_audio = stego.WavAudio(None, original_samples[:])
    eligible = original_audio.eligible_indices()
    positions = prng.shuffled_positions(k_embed, eligible)
    used_bits = len(full_payload) * 8
    assert used_bits <= len(positions)

    embedded_audio = stego.WavAudio(None, original_samples[:])
    stego.embed(embedded_audio, full_payload, positions)
    extracted = stego.extract(embedded_audio, positions, used_bits)
    assert extracted == full_payload
    assert embedded_audio.eligible_indices() == eligible

    payload_bits = list(stego.bytes_to_bits(full_payload))
    embedding_examples = []
    for bit_index in range(min(32, used_bits)):
        position = positions[bit_index]
        before = original_samples[position]
        after = embedded_audio.samples[position]
        embedding_examples.append(
            {
                "bitIndex": bit_index,
                "payloadByteIndex": bit_index // 8,
                "bitWithinByteMsbFirst": bit_index % 8,
                "payloadBit": payload_bits[bit_index],
                "sampleIndex": position,
                "before": before,
                "beforeLsb": before & 1,
                "after": after,
                "afterLsb": after & 1,
                "delta": after - before,
            }
        )

    changed = sum(
        before != after
        for before, after in zip(original_samples, embedded_audio.samples)
    )
    deltas = [
        embedded_audio.samples[position] - original_samples[position]
        for position in positions[:used_bits]
    ]
    noise_energy = sum(delta * delta for delta in deltas)
    signal_energy = sum(sample * sample for sample in original_samples)
    mse = noise_energy / len(original_samples)
    snr_db = (
        10 * math.log10(signal_energy / noise_energy)
        if noise_energy
        else math.inf
    )
    ones = sum(payload_bits)
    zeros = used_bits - ones
    chi_squared = (
        (zeros - used_bits / 2) ** 2 + (ones - used_bits / 2) ** 2
    ) / (used_bits / 2)

    # The avalanche metric flips each of the 128 input bits once and measures
    # the Hamming distance from the same deterministic base ciphertext block.
    base_cipher = cipher.encrypt_block(x1, round_keys)
    avalanche_counts = []
    for bit_index in range(128):
        variant = bytearray(x1)
        variant[bit_index // 8] ^= 1 << (7 - bit_index % 8)
        changed_cipher = cipher.encrypt_block(bytes(variant), round_keys)
        avalanche_counts.append(
            sum((a ^ b).bit_count() for a, b in zip(base_cipher, changed_cipher))
        )

    flipped_input = bytearray(x1)
    flipped_input[0] ^= 0x80
    variant_trace = trace_block(bytes(flipped_input), round_keys)
    diffusion_timeline = []
    base_stages = [
        ("input", block_trace["input"]),
        ("initial whitening", block_trace["initialWhitening"]),
    ] + [
        (f"round {round_data['round']}", round_data["addRoundKey"])
        for round_data in block_trace["rounds"]
    ]
    variant_stages = [
        ("input", variant_trace["input"]),
        ("initial whitening", variant_trace["initialWhitening"]),
    ] + [
        (f"round {round_data['round']}", round_data["addRoundKey"])
        for round_data in variant_trace["rounds"]
    ]
    for (stage, base_state), (_, variant_state) in zip(base_stages, variant_stages):
        left = bytes.fromhex(base_state["bytesHex"])
        right = bytes.fromhex(variant_state["bytesHex"])
        diffusion_timeline.append(
            {
                "stage": stage,
                "base": base_state,
                "oneBitVariant": variant_state,
                **byte_diff(left, right),
            }
        )

    first_round_base = block_trace["rounds"][0]
    first_round_variant = variant_trace["rounds"][0]
    first_round_diffusion = []
    for stage_name in ("subBytes", "shiftRows", "mixColumns", "addRoundKey"):
        base_state = first_round_base[stage_name]
        variant_state = first_round_variant[stage_name]
        first_round_diffusion.append(
            {
                "stage": stage_name,
                "base": base_state,
                "oneBitVariant": variant_state,
                **byte_diff(
                    bytes.fromhex(base_state["bytesHex"]),
                    bytes.fromhex(variant_state["bytesHex"]),
                ),
            }
        )

    mds_product = cipher.mat_mul_gf(cipher.INV_MDS, cipher.MDS)
    assert cipher.is_identity(mds_product)
    assert len(set(cipher.SBOX)) == 256
    assert all(cipher.INV_SBOX[cipher.SBOX[index]] == index for index in range(256))

    tag_offset = payload.HEADER_LEN + len(ciphertext)
    fields = [
        {
            "name": "magic",
            "offset": 0,
            "sizeBytes": 4,
            "hex": full_payload[0:4].hex(),
            "meaning": 'SHA256(K_embed || "VFC-MAGIC")[:4]',
        },
        {
            "name": "version",
            "offset": 4,
            "sizeBytes": 1,
            "hex": full_payload[4:5].hex(),
            "value": full_payload[4],
        },
        {
            "name": "flags",
            "offset": 5,
            "sizeBytes": 1,
            "hex": full_payload[5:6].hex(),
            "value": full_payload[5],
        },
        {
            "name": "salt",
            "offset": 6,
            "sizeBytes": 16,
            "hex": full_payload[6:22].hex(),
        },
        {
            "name": "iv",
            "offset": 22,
            "sizeBytes": 16,
            "hex": full_payload[22:38].hex(),
        },
        {
            "name": "frame_no",
            "offset": 38,
            "sizeBytes": 4,
            "hex": full_payload[38:42].hex(),
            "value": FRAME_NO,
        },
        {
            "name": "ct_len",
            "offset": 42,
            "sizeBytes": 8,
            "hex": full_payload[42:50].hex(),
            "value": len(ciphertext),
        },
        {
            "name": "ciphertext",
            "offset": payload.HEADER_LEN,
            "sizeBytes": len(ciphertext),
            "hex": ciphertext.hex(),
        },
        {
            "name": "hmac_sha256_tag",
            "offset": tag_offset,
            "sizeBytes": payload.TAG_LEN,
            "hex": full_payload[tag_offset:].hex(),
        },
    ]

    eligible_set = set(eligible)
    ineligible = [
        {
            "index": index,
            "sample": original_samples[index],
            "sampleShifted": original_samples[index] >> 1,
            "eligible": False,
        }
        for index in range(len(original_samples))
        if index not in eligible_set
    ][:12]
    eligible_examples = [
        {
            "index": index,
            "sample": original_samples[index],
            "sampleShifted": original_samples[index] >> 1,
            "eligible": True,
        }
        for index in eligible[:12]
    ]

    validations = {
        "fingerprintMatchesImplementation": True,
        "roundTraceMatchesEncryptBlock": True,
        "cbcRoundTripExact": True,
        "payloadHeaderRoundTripExact": True,
        "payloadHmacVerified": True,
        "singleCiphertextBitTamperRejected": tamper_rejected,
        "audioPayloadExtractedExactly": extracted == full_payload,
        "audioEligibilityInvariantAfterLsbReplacement": (
            embedded_audio.eligible_indices() == eligible
        ),
        "mdsInverseProductIsIdentity": cipher.is_identity(mds_product),
        "sboxIsBijective": len(set(cipher.SBOX)) == 256,
    }
    assert all(validations.values())

    return {
        "schemaVersion": 1,
        "fixtureNotice": (
            "Deterministic public teaching vector generated by "
            "generate_vfc_trace.py; never use its fixed salt or IV for secrets."
        ),
        "implementation": {
            "name": "VFC",
            "version": "0.2",
            "sourceSha256": source_hashes(),
        },
        "testSuite": test_suite,
        "inputs": {
            "passwordAscii": PASSWORD.decode("ascii"),
            "passwordHex": PASSWORD.hex(),
            "frameNumber": FRAME_NO,
            "frameNumberBe32Hex": FRAME_NO.to_bytes(4, "big").hex(),
            "saltHex": SALT.hex(),
            "ivHex": IV.hex(),
            "filename": FILENAME,
            "secretUtf8": SECRET.decode("utf-8"),
            "secretHex": SECRET.hex(),
        },
        "fingerprint": fp_trace,
        "kdf": {
            "importantOrdering": (
                "PBKDF2's salt argument is domainLabel || fingerprint || "
                "frameBE32, followed by randomSalt only for K_enc and K_auth."
            ),
            "embedding": kdf_record(
                purpose="deterministic embedding positions (salt-independent)",
                label=b"VFC-EMBED",
                fingerprint_bytes=fp,
                salt=b"",
                output=k_embed,
            ),
            "encryption": kdf_record(
                purpose="block cipher key material",
                label=b"VFC-ENCRYPT",
                fingerprint_bytes=fp,
                salt=SALT,
                output=k_enc,
            ),
            "authentication": kdf_record(
                purpose="HMAC-SHA256 key material",
                label=b"VFC-AUTH",
                fingerprint_bytes=fp,
                salt=SALT,
                output=k_auth,
            ),
            "derivedMagicHex": keys.compute_magic(k_embed).hex(),
        },
        "cipher": {
            "blockBytes": 16,
            "rounds": cipher.ROUNDS,
            "stateLayout": "4x4 bytes, column-major serialization",
            "gfPolynomialHex": "0x11b",
            "mds": cipher.MDS,
            "inverseMds": cipher.INV_MDS,
            "inverseTimesMds": mds_product,
            "sboxSeedAscii": "VFC-SBOX-v0.2",
            "sbox": cipher.SBOX,
            "inverseSbox": cipher.INV_SBOX,
            "roundKeyDerivation": 'SHA256(K_enc || "VFC-RK" || roundBE16)[:16]',
            "roundKeys": [
                {
                    "round": index,
                    "hex": round_key.hex(),
                    "gridHex": state_record(cipher._to_state(round_key))["gridHex"],
                }
                for index, round_key in enumerate(round_keys)
            ],
            "blockTraceInputMeaning": "CBC block 1 input: padded P1 XOR IV",
            "blockTrace": block_trace,
            "oneBitFlip": {
                "bitIndex": 0,
                "bitConvention": "MSB-first",
                "inputHex": x1.hex(),
                "variantInputHex": bytes(flipped_input).hex(),
                "firstRoundLayerDiffusion": first_round_diffusion,
                "roundOutputDiffusion": diffusion_timeline,
            },
        },
        "cbc": {
            "filenameMetadataPlaintext": {
                "layout": (
                    "name_len(2) || filename || original_size(8) || "
                    "compression_flags(1) || file_bytes"
                ),
                "compressionRequested": False,
                "compressionFlags": 0,
                "hex": inner_plaintext.hex(),
                "bytes": len(inner_plaintext),
            },
            "padding": {
                "scheme": "PKCS#7",
                "paddingLength": padded[-1],
                "paddingByteHex": f"{padded[-1]:02x}",
                "paddedHex": padded.hex(),
                "paddedBytes": len(padded),
            },
            "ivHex": IV.hex(),
            "blocks": [
                {
                    "block": 1,
                    "plaintextHex": p1.hex(),
                    "previousHex": IV.hex(),
                    "xorInputHex": x1.hex(),
                    "ciphertextHex": c1.hex(),
                },
                {
                    "block": 2,
                    "plaintextHex": p2.hex(),
                    "previousHex": c1.hex(),
                    "xorInputHex": x2.hex(),
                    "ciphertextHex": c2.hex(),
                },
            ],
            "ciphertextHex": ciphertext.hex(),
            "ciphertextBytes": len(ciphertext),
            "decryptsExactly": True,
        },
        "payload": {
            "layout": "header(50) || ciphertext(variable) || HMAC-SHA256 tag(32)",
            "headerBytes": payload.HEADER_LEN,
            "ciphertextBytes": len(ciphertext),
            "tagBytes": payload.TAG_LEN,
            "totalBytes": len(full_payload),
            "authenticatedRange": {
                "startInclusive": 0,
                "endExclusive": tag_offset,
                "bytes": tag_offset,
            },
            "fields": fields,
            "fullHex": full_payload.hex(),
        },
        "audioEmbedding": {
            "fixture": (
                "one second / 48,000 mono signed 16-bit PCM samples from "
                "the deterministic vfc/tests.py carrier formula"
            ),
            "sampleRateHz": 48_000,
            "channels": 1,
            "sampleFormat": "signed 16-bit PCM",
            "eligibilityRule": "abs(sample >> 1) >= 2",
            "eligibilityThreshold": stego.THRESHOLD,
            "totalSamples": len(original_samples),
            "eligibleSamples": len(eligible),
            "ineligibleSamples": len(original_samples) - len(eligible),
            "eligibleExamples": eligible_examples,
            "ineligibleExamples": ineligible,
            "shuffle": "unbiased Fisher-Yates driven by SHA256(K_embed || counterBE64)",
            "first32ShuffledPositions": positions[:32],
            "positionsAreUnique": len(set(positions)) == len(positions),
            "payloadBytes": len(full_payload),
            "usedSamples": used_bits,
            "capacityPercent": 100 * used_bits / len(eligible),
            "payloadBitsFirst64": payload_bits[:64],
            "embeddingExamples": embedding_examples,
            "extractedPayloadMatches": extracted == full_payload,
        },
        "measurements": {
            "audio": {
                "changedSamples": changed,
                "unchangedUsedSamples": used_bits - changed,
                "deltaCounts": {
                    "minusOne": deltas.count(-1),
                    "zero": deltas.count(0),
                    "plusOne": deltas.count(1),
                },
                "maxAbsoluteDelta": max(abs(delta) for delta in deltas),
                "meanSquaredErrorAcrossCarrier": mse,
                "signalToNoiseRatioDb": snr_db,
                "embeddedBitZeros": zeros,
                "embeddedBitOnes": ones,
                "embeddedLsbChiSquared": chi_squared,
                "scope": "this deterministic one-second synthetic carrier only",
            },
            "avalanche": {
                "method": (
                    "flip each of 128 input bits independently; compare each "
                    "ciphertext with the same base ciphertext"
                ),
                "trials": 128,
                "baseInputHex": x1.hex(),
                "baseCiphertextHex": base_cipher.hex(),
                "averageChangedBits": statistics.mean(avalanche_counts),
                "averageChangedPercent": (
                    100 * statistics.mean(avalanche_counts) / 128
                ),
                "minimumChangedBits": min(avalanche_counts),
                "maximumChangedBits": max(avalanche_counts),
                "countsByInputBit": avalanche_counts,
                "scope": "one deterministic block/key teaching vector, not a security proof",
            },
        },
        "validation": {
            "assertionCount": len(validations),
            "assertions": validations,
        },
    }


def write_typescript(output: Path, trace: dict) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    # Prettier is run by the Remotion lint/build workflow.  Compact JSON keeps
    # regeneration deterministic without making Python depend on Node tooling.
    serialized = json.dumps(trace, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    content = (
        "/* AUTO-GENERATED by /home/mobta/university/Crypto/"
        "generate_vfc_trace.py. */\n"
        "/* Run the generator again after changing the Python implementation. */\n\n"
        f"export const vfcTrace = {serialized} as const;\n\n"
        "export type VfcTrace = typeof vfcTrace;\n"
    )
    output.write_text(content, encoding="utf-8")



def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    trace = build_trace()
    write_typescript(args.output, trace)
    print(f"wrote {args.output}")
    print(
        "fingerprint={fingerprint} payload={payload}B positions={positions} "
        "avalanche={avalanche:.3f}% snr={snr:.3f}dB tests={tests} "
        "validations={validations}".format(
            fingerprint=trace["fingerprint"]["bytesHex"],
            payload=trace["payload"]["totalBytes"],
            positions=trace["audioEmbedding"]["usedSamples"],
            avalanche=trace["measurements"]["avalanche"]["averageChangedPercent"],
            snr=trace["measurements"]["audio"]["signalToNoiseRatioDb"],
            tests=(
                f'{trace["testSuite"]["passedCount"]}/'
                f'{trace["testSuite"]["count"]}'
            ),
            validations=trace["validation"]["assertionCount"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
