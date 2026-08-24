import os,sys,json,base64,struct

import x_mssdk_info


def decrypt_x_mssdk_info(token_str: str) -> tuple:
    token_str = "".join(token_str.split())
    if token_str.lower().startswith("x-mssdk-info:"):
        token_str = token_str.split(":", 1)[1].strip()

    seed_str = token_str[:4]
    b64_part = token_str[4:]

    try:
        enc_bytes = base64.b64decode(b64_part)
    except Exception:
        enc_bytes = base64.b64decode(b64_part + "==")

    seed_bytes = seed_str.encode('latin1')
    key = x_mssdk_info._to_words(seed_bytes, False)
    while len(key) < 4:
        key.append(0)

    n_words = len(enc_bytes) // 4
    enc_words = list(struct.unpack(f"<{n_words}I", enc_bytes[:n_words * 4]))

    dec_words = x_mssdk_info.xxtea_decrypt(enc_words, key[:4])
    payload_len = dec_words[-1]

    dec_bytes = x_mssdk_info._words_to_bytes(dec_words[:-1])[:payload_len]
    data = json.loads(dec_bytes.decode('utf-8'))
    return data, seed_str


def main():
    if len(sys.argv) > 1:
        token = sys.argv[1]
    else:
        token = x_mssdk_info.get_X_Mssdk_Info()

    data, seed = decrypt_x_mssdk_info(token)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_filename = os.path.join(script_dir, "decrypted.json")
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

  
    print("TikTok X-Mssdk-Info Decrypter version (v5.3.1)")
    print(f"Decrypted Key Seed : {repr(seed)}")
    print(f"Payload Timestamp  : {data.get('timestamp')}")
    print(f"Top-Level Keys     : {list(data.keys())}")
    print(f"Decrypted data saved in: {output_filename}")
    print("=" * 60)


if __name__ == "__main__":
    main()
