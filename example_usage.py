import json
from x_mssdk_info import get_X_Mssdk_Info
from x_mssdk_info_decrypter import decrypt_x_mssdk_info

def main():
    print(" 1. GENERATE A NEW X-MSSDK-INFO HEADER")
 

    custom_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    custom_fingerprint = {
        "navigator": {
            "hardwareConcurrency": 8,
            "platform": "Win32"
        },
        "window": {
            "innerWidth": 1920,
            "innerHeight": 1080
        }
    }

    token = get_X_Mssdk_Info(fingerprint=custom_fingerprint, user_agent=custom_ua)
    print(f"Generated Token : {token[:60]}... (Length: {len(token)})")
    print(f"Key Seed Prefix : {repr(token[:4])}")

    print(" 2. DECRYPT THE GENERATED TOKEN (ROUND-TRIP VERIFICATION)")


    decrypted_data, extracted_seed = decrypt_x_mssdk_info(token)
    print(f"Extracted Seed  : {repr(extracted_seed)}")
    print(f"Timestamp       : {decrypted_data.get('timestamp')}")
    print(f"Screen Res      : {decrypted_data.get('window', {}).get('innerWidth')}x{decrypted_data.get('window', {}).get('innerHeight')}")
    print(f"CPU Cores       : {decrypted_data.get('navigator', {}).get('hardwareConcurrency')}")
    print(f"WebGL Extensions: {len(decrypted_data.get('webgl', {}).get('supportedExtensions', []))} items")

    print("\n" + "=" * 65)
    print(" 3. ATTACH TO HTTP REQUEST (SAMPLE HEADERS)")
    print("=" * 65)

    headers = {
        "User-Agent": custom_ua,
        "Referer": "https://www.tiktok.com/",
        "X-Mssdk-Info": token
    }
    print(json.dumps(headers, indent=2))
    print("\nverification Complete")

if __name__ == "__main__":
    main()
