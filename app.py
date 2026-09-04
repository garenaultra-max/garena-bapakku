from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import requests
import string
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import json
import codecs
import time
import urllib3
import base64
import concurrent.futures
import threading
import re

# Nonaktifkan peringatan SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# -------------------- KONFIGURASI CORS -------------------- #
CORS(app, resources={
    r"/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization", "X-Requested-With"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True,
        "max_age": 3600
    }
})

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response

# -------------------- KUNCI & KONSTANTA -------------------- #
HEX_KEY = "32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533"
key = bytes.fromhex(HEX_KEY)

REGION_LANG = {
    "ME": "ar", "IND": "hi", "ID": "id", "VN": "vi", "TH": "th",
    "BD": "bn", "PK": "ur", "TW": "zh", "EU": "en", "RU": "ru",
    "NA": "en", "SAC": "es", "BR": "pt", "CIS": "ru"
}

REGION_URLS = {
    "IND": "https://client.ind.freefiremobile.com/",
    "ID": "https://clientbp.ggblueshark.com/",
    "BR": "https://client.us.freefiremobile.com/",
    "ME": "https://clientbp.common.ggbluefox.com/",
    "VN": "https://clientbp.ggblueshark.com/",
    "TH": "https://clientbp.common.ggbluefox.com/",
    "RU": "https://clientbp.ggblueshark.com/",
    "BD": "https://clientbp.ggblueshark.com/",
    "PK": "https://clientbp.ggblueshark.com/",
    "SG": "https://clientbp.ggblueshark.com/",
    "NA": "https://client.us.freefiremobile.com/",
    "SAC": "https://client.us.freefiremobile.com/",
    "EU": "https://clientbp.ggblueshark.com/",
    "TW": "https://clientbp.ggblueshark.com/",
    "CIS": "https://clientbp.ggblueshark.com/"
}

# -------------------- DETEKSI POLA LANGKA -------------------- #
PATTERNS = {
    "R4": [r"(\d)\1{3,}", 3], "R3": [r"(\d)\1\1(\d)\2\2", 2],
    "S5": [r"(12345|23456|34567|45678|56789)", 4],
    "S4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 3],
    "P6": [r"^(\d)(\d)(\d)\3\2\1$", 5], "P4": [r"^(\d)(\d)\2\1$", 3],
    "SPH": [r"(69|420|1337|007)", 4], "SPM": [r"(100|200|300|400|500|666|777|888|999)", 2],
    "QD": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 4],
    "MH": [r"^(\d{2,3})\1$", 3], "MM": [r"(\d{2})0\1", 2], "GD": [r"1618|0618", 3]
}

def detect_rare_pattern(uid):
    uid_str = str(uid)
    max_score = 0
    matched_patterns = []
    for name, (pattern, score) in PATTERNS.items():
        matches = re.findall(pattern, uid_str)
        if matches:
            matched_patterns.append({"name": name, "score": score, "match": matches[0]})
            if score > max_score:
                max_score = score
    if matched_patterns:
        matched_patterns.sort(key=lambda x: x["score"], reverse=True)
        return True, matched_patterns[0]["name"], max_score, matched_patterns
    return False, None, 0, []

# -------------------- OPTIMASI -------------------- #
OPTIMIZATION = {'timeout': 30, 'max_retries': 3}
EXIT_FLAG = False

# -------------------- SESSION (Thread-Local) -------------------- #
thread_local = threading.local()

def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        thread_local.session.mount("http://", adapter)
        thread_local.session.mount("https://", adapter)
    return thread_local.session

# -------------------- SPOOF IP & WAF BYPASS -------------------- #
class FastIPSpoofer:
    @staticmethod
    def get_ip_fast():
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

class WAFBypass:
    @staticmethod
    def get_ua():
        agents = [
            "GarenaMSDK/4.0.19P8(ASUS_Z01QD ;Android 12;en;US;)",
            "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
            "GarenaMSDK/4.0.19P8(Redmi Note 8 ;Android 10;en;US;)",
            "GarenaMSDK/4.0.19P8(Pixel 3 ;Android 11;en;US;)"
        ]
        return random.choice(agents)

# -------------------- PROTOBUF & ENKRIPSI -------------------- #
def EnC_Vr(N):
    H = []
    while True:
        BesTo = N & 0x7F
        N >>= 7
        if N: BesTo |= 0x80
        H.append(BesTo)
        if not N: break
    return bytes(H)

def CrEaTe_VarianT(field_number, value):
    return EnC_Vr((field_number << 3) | 0) + EnC_Vr(value)

def CrEaTe_LenGTh(field_number, value):
    encoded = value.encode() if isinstance(value, str) else value
    return EnC_Vr((field_number << 3) | 2) + EnC_Vr(len(encoded)) + encoded

def CrEaTe_ProTo(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        else:
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

build_proto = CrEaTe_ProTo

def encrypt_api(plain_text):
    plain = bytes.fromhex(plain_text)
    key_bytes = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

aes_encrypt = encrypt_api

# -------------------- GENERATE NAMA & PASSWORD -------------------- #
def generate_random_name(prefix):
    return prefix + ''.join(random.choices(string.ascii_letters + string.digits, k=6)).upper()

def generate_custom_password(prefix="SPIDER"):
    return f"{prefix}-{''.join(random.choices(string.ascii_letters + string.digits, k=9)).upper()}-CORE"

# -------------------- FUNGSI UTAMA PEMBUATAN AKUN -------------------- #
# ========== API FUNCTIONS (ACCOUNT CREATION) ==========
def create_account(region, account_name, password_prefix, is_ghost):
    if EXIT_FLAG: return None
    try:
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"{password_prefix}_{rand_part}"
        
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {
            "app_id": 100067,
            "client_type": 2,
            "password": password,
            "source": 2
        }
        body_json = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(HEX_KEY, body_json.encode("utf-8"), hashlib.sha256).hexdigest()
        
        headers = {
            "User-Agent": WAFBypass.get_ua(),
            "Connection": "Keep-Alive",
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
            "Authorization": f"Signature {signature}",
            "Content-Type": "application/json; charset=utf-8",
            "Host": "100067.connect.garena.com",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        
        resp = get_session().post(url, headers=headers, data=body_json)
        if resp and resp.status_code == 200:
            res = resp.json()
            if "data" in res and "uid" in res["data"]:
                uid = res["data"]["uid"]
                return get_token(uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def get_token(uid, password, region, account_name, password_prefix, is_ghost):
    if EXIT_FLAG: return None
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": WAFBypass.get_ua(),
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        resp = get_session().post(url, headers=headers, data=body)
        
        if resp and resp.status_code == 200 and 'open_id' in resp.json():
            open_id = resp.json()['open_id']
            access_token = resp.json()["access_token"]
            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = ""
            for i in range(len(open_id)):
                encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost)
        return None
    except:
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, is_ghost):
    if EXIT_FLAG: return None
    try:
        url = "https://loginbp.ggpolarbear.com/MajorRegister" if is_ghost or region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorRegister"
        name = generate_random_name(account_name)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": WAFBypass.get_ua(),
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: lang, 16: 1, 17: 1}
        payload_bytes = build_proto(payload)
        encrypted = aes_encrypt(payload_bytes.hex())
        get_session().post(url, headers=headers, data=encrypted)
        login_result = major_login(uid, password, access_token, open_id, region, is_ghost)
        account_id = login_result.get("account_id", "N/A")
        jwt_token = login_result.get("jwt_token", "")
        if account_id != "N/A":
            if not is_ghost and jwt_token and region.upper() != "BR":
                try: force_region_bind(region, jwt_token)
                except: pass
            return {
                "uid": uid, 
                "password": password, 
                "name": name,
                "region": "GHOST" if is_ghost else region,
                "account_id": account_id, 
                "jwt_token": jwt_token,
                "created_at": datetime.now().isoformat()
            }
        return None
    except:
        return None

def major_login(uid, password, access_token, open_id, region, is_ghost):
    try:
        lang = "pt" if is_ghost else REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        url = "https://loginbp.ggpolarbear.com/MajorLogin" if is_ghost or region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "ReleaseVersion": "OB54",
            "User-Agent": WAFBypass.get_ua(),
            "X-GA": "v1 1",
            "X-Unity-Version": "2018.4.11f1",
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        data = payload.replace(b'afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390', access_token.encode())
        data = data.replace(b'1d8ec0240ede109973f3321b9354b44d', open_id.encode())
        d = encrypt_api(data.hex())
        resp = get_session().post(url, headers=headers, data=bytes.fromhex(d))
        if resp and resp.status_code == 200 and len(resp.text) > 10:
            jwt_start = resp.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = resp.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            payload_part = parts[1]
                            padding = 4 - len(payload_part) % 4
                            if padding != 4:
                                payload_part += '=' * padding
                            decoded = base64.urlsafe_b64decode(payload_part)
                            data = json.loads(decoded)
                            account_id = data.get('account_id') or data.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token}
                    except: pass
        return {"account_id": "N/A", "jwt_token": ""}
    except:
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    try:
        url = "https://loginbp.common.ggbluefox.com/ChooseRegion" if region.upper() in ["ME","TH"] else "https://loginbp.ggpolarbear.com/ChooseRegion"
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        proto_data = build_proto({1: region_code})
        encrypted = encrypt_api(proto_data.hex())
        headers = {
            'Content-Type': "application/x-www-form-urlencoded",
            'Authorization': f"Bearer {jwt_token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB54",
            'X-Forwarded-For': FastIPSpoofer.get_ip(),
            'X-Real-IP': FastIPSpoofer.get_ip(),
        }
        get_session().post(url, data=bytes.fromhex(encrypted), headers=headers)
    except: pass
    
def create_acc(region, name_prefix, password_prefix, is_ghost=False):
    password = generate_custom_password(password_prefix)
    ip = FastIPSpoofer.get_ip_fast()
    url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
    payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
    body_json = json.dumps(payload, separators=(",", ":"))
    signature = hmac.new(key, body_json.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "User-Agent": WAFBypass.get_ua(),
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "Accept-Encoding": "deflate, gzip",
        "X-Unity-Version": "2022.3.47f1.",
        "Connection": "Keep-Alive",
        "Authorization": f"Signature {signature}",
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
    }
    try:
        resp = get_session().post(url, headers=headers, json=payload, timeout=OPTIMIZATION['timeout'], verify=False)
        uid = resp.json().get('data', {}).get('uid')
        if uid:
            return get_token(uid, password, region, name_prefix, password_prefix, is_ghost)
    except:
        pass
    return None

def create_single_account(args):
    name_prefix, region, password_prefix, is_ghost = args
    for attempt in range(OPTIMIZATION['max_retries']):
        try:
            result = create_account(region, name_prefix, password_prefix, is_ghost)
            if result and result.get('uid') and result.get('status') == "success":
                return result
            time.sleep(1)
        except:
            time.sleep(1)
    return None

# -------------------- ROUTES FLASK -------------------- #
@app.route('/gen', methods=['GET', 'OPTIONS'])
def generate_accounts():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    name = request.args.get('name', 'HUSTLER')
    count = request.args.get('count', '1')
    region = request.args.get('region', 'IND').upper()
    password_prefix = request.args.get('password_prefix', 'SPIDER')
    is_ghost = request.args.get('ghost', 'false').lower() == 'true'
    detect_rare = request.args.get('detect_rare', 'true').lower() == 'true'
    try:
        count = max(1, int(count))
    except:
        count = 1
    if region not in REGION_LANG and not is_ghost:
        region = "IND"

    print(f"Memulai pembuatan {count} akun untuk region {region} dengan prefix {name}")
    max_workers = min(count, 10)
    results = []
    rare_accounts = []
    attempts = 0
    max_total_attempts = count * 3

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        while len(results) < count and attempts < max_total_attempts:
            needed = count - len(results)
            current_batch = min(needed, max_workers)
            futures = [executor.submit(create_single_account, (name, region, password_prefix, is_ghost)) for _ in range(current_batch)]
            for future in concurrent.futures.as_completed(futures):
                attempts += 1
                result = future.result()
                if result and result.get('status') == "success":
                    if detect_rare and result.get('is_rare', False):
                        rare_accounts.append(result)
                        print(f"🔥 AKUN LANGKA! ID: {result['account_id']}, Pola: {result.get('rare_pattern', 'Unknown')}, Skor: {result.get('rare_score', 0)}")
                    results.append(result)
                    print(f"Berhasil membuat akun {len(results)}/{count}: UID {result['uid']}, AccountID: {result.get('account_id', 'N/A')}")
                if len(results) >= count:
                    break
            if len(results) < count:
                time.sleep(1)

    response_data = {
        "success": True,
        "total_requested": count,
        "total_created": len(results),
        "accounts": results,
        "attempts_made": attempts,
        "rare_count": len(rare_accounts) if detect_rare else 0
    }
    if detect_rare and rare_accounts:
        response_data["rare_accounts"] = rare_accounts
    print(f"Selesai: {len(results)} akun dibuat dari {count} yang diminta")
    return jsonify(response_data)

@app.route('/patterns', methods=['GET', 'OPTIONS'])
def get_patterns():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    patterns_info = [{"name": n, "pattern": p[0], "score": p[1]} for n, p in PATTERNS.items()]
    return jsonify({"total_patterns": len(patterns_info), "patterns": patterns_info})

@app.route('/', methods=['GET', 'OPTIONS'])
def home():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    return jsonify({
        "message": "FreeFire Account Generator API - Tanpa Batas",
        "endpoint": "/gen?name=NAME&count=COUNT&region=REGION&password_prefix=PREFIX&ghost=BOOLEAN&detect_rare=BOOLEAN",
        "max_count": "UNLIMITED",
        "available_regions": list(REGION_LANG.keys()),
        "features": {
            "rare_pattern_detection": "Mendeteksi pola UID langka (R4, R3, S5, S4, P6, P4, SPH, SPM, QD, MH, MM, GD, PAIR3, PAIRX, ALT, ALT8, TAIL0, HEAD1, BLOCK, STEP2, MIX)",
            "ghost_mode": "Buat akun region GHOST",
            "unlimited_generation": "Tidak ada batasan jumlah akun",
            "cors_enabled": "API dapat diakses dari domain mana pun"
        },
        "note": "Proses lengkap: register → token → major register → major login → bind region",
        "patterns_endpoint": "/patterns - Lihat semua pola langka"
    })

@app.route('/health', methods=['GET', 'OPTIONS'])
def health():
    if request.method == 'OPTIONS':
        return jsonify({'status': 'ok'})
    return jsonify({"status": "healthy", "message": "API berjalan"})

# -------------------- UNTUK DEPLOY (WSGI) -------------------- #
def application(environ, start_response):
    return app(environ, start_response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000, debug=False)
