# api/index.py
from flask import Flask, request, jsonify, make_response
import os, sys, time, threading, json, random, requests, re, codecs, base64, hmac, hashlib
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import concurrent.futures

urllib3.disable_warnings()

# ========== CONFIG ==========
REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"}
REGION_NAMES = {"ME":"Middle East","IND":"India","ID":"Indonesia","VN":"Vietnam","TH":"Thailand","BD":"Bangladesh","PK":"Pakistan","TW":"Taiwan","CIS":"CIS","SAC":"South America","BR":"Brazil"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
OPT = {'timeout': 30, 'retries': 3, 'backoff': 0.5}
RARITY_SCORE_THRESHOLD = 8

# ========== IP SPOOFING ==========
class FastIPSpoofer:
    _IP_POOL = []
    _IP_INDEX = 0
    _IP_LOCK = threading.Lock()
    @classmethod
    def init_ip_pool(cls, count=5000):
        if not cls._IP_POOL:
            for _ in range(count):
                a = random.randint(1,254)
                b = random.randint(0,255)
                c = random.randint(0,255)
                d = random.randint(1,254)
                cls._IP_POOL.append(f"{a}.{b}.{c}.{d}")
    @classmethod
    def get_ip(cls):
        with cls._IP_LOCK:
            ip = cls._IP_POOL[cls._IP_INDEX % len(cls._IP_POOL)]
            cls._IP_INDEX += 1
            return ip
FastIPSpoofer.init_ip_pool(5000)

class WAFBypass:
    _uas = [
        "GarenaMSDK/4.0.42(SM-A525F ;Android)",
        "GarenaMSDK/4.0.39(SM-A325M;Android 13;en;HK;)",
        "GarenaMSDK/4.0.38(Redmi Note 10;Android 12;en;ID;)",
        "GarenaMSDK/4.0.40(Poco X3;Android 11;en;SG;)",
        "GarenaMSDK/4.0.41(SM-S918B;Android 14;en;IN;)",
        "GarenaMSDK/4.0.42(OnePlus 11;Android 13;en;US;)",
        "GarenaMSDK/4.0.39(Xiaomi 13 Pro;Android 13;pt;BR;)",
        "GarenaMSDK/4.0.40(Pixel 7 Pro;Android 14;en;US;)",
    ]
    @staticmethod
    def get_ua():
        return random.choice(WAFBypass._uas)

session = requests.Session()

def request_retry(method, url, **kwargs):
    for attempt in range(OPT['retries'] + 1):
        try:
            if 'timeout' not in kwargs:
                kwargs['timeout'] = OPT['timeout']
            if 'headers' not in kwargs:
                kwargs['headers'] = {}
            kwargs['verify'] = False
            resp = session.request(method, url, **kwargs)
            if resp.status_code in [429,500,502,503,504,408]:
                if attempt < OPT['retries']:
                    time.sleep(OPT['backoff'] * (attempt + 1))
                    continue
            return resp
        except:
            if attempt < OPT['retries']:
                time.sleep(OPT['backoff'] * (attempt + 1))
                continue
            return None
    return None

# ========== ENCRYPTION ==========
def encode_varint(n):
    if n < 0: return b''
    result = []
    while True:
        byte = n & 0x7F
        n >>= 7
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        header = (field_num << 3) | 0
        return encode_varint(header) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        encoded_val = value.encode() if isinstance(value, str) else value
        header = (field_num << 3) | 2
        return encode_varint(header) + encode_varint(len(encoded_val)) + encoded_val
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    key = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
    iv = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plain, AES.block_size)).hex()

# ========== API FUNCTIONS ==========
def create_account(region, account_name, password_prefix):
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
        
        resp = request_retry('POST', url, headers=headers, data=body_json)
        if resp and resp.status_code == 200:
            res = resp.json()
            if "data" in res and "uid" in res["data"]:
                uid = res["data"]["uid"]
                return get_token(uid, password, region, account_name, password_prefix)
        return None
    except:
        return None

def get_token(uid, password, region, account_name, password_prefix):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": WAFBypass.get_ua(),
            "X-Forwarded-For": FastIPSpoofer.get_ip(),
            "X-Real-IP": FastIPSpoofer.get_ip(),
        }
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY, "client_id": "100067"}
        resp = request_retry('POST', url, headers=headers, data=body)
        
        if resp and resp.status_code == 200 and 'open_id' in resp.json():
            open_id = resp.json()['open_id']
            access_token = resp.json()["access_token"]
            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = ""
            for i in range(len(open_id)):
                encoded += chr(ord(open_id[i]) ^ keystream[i % len(keystream)])
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix)
        return None
    except:
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix):
    try:
        url = "https://loginbp.ggpolarbear.com/MajorRegister" if region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorRegister"
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
        lang = REGION_LANG.get(region.upper(), "en")
        payload = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: field, 15: lang, 16: 1, 17: 1}
        payload_bytes = build_proto(payload)
        encrypted = aes_encrypt(payload_bytes.hex())
        request_retry('POST', url, headers=headers, data=encrypted)
        login_result = major_login(uid, password, access_token, open_id, region)
        account_id = login_result.get("account_id", "N/A")
        jwt_token = login_result.get("jwt_token", "")
        if account_id != "N/A":
            if jwt_token and region.upper() != "BR":
                try: force_region_bind(region, jwt_token)
                except: pass
            return {
                "uid": uid, 
                "password": password, 
                "name": name,
                "region": region,
                "account_id": account_id, 
                "jwt_token": jwt_token,
                "created_at": datetime.now().isoformat()
            }
        return None
    except:
        return None

def major_login(uid, password, access_token, open_id, region):
    try:
        lang = REGION_LANG.get(region.upper(), "en")
        payload_parts = [
            b'\x1a\x132025-08-30 05:19:21"\tfree fire(\x01:\x081.114.13B2Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)J\x08HandheldR\nATM MobilsZ\x04WIFI`\xb6\nh\xee\x05r\x03300z\x1fARMv7 VFPv3 NEON VMH | 2400 | 2\x80\x01\xc9\x0f\x8a\x01\x0fAdreno (TM) 640\x92\x01\rOpenGL ES 3.2\x9a\x01+Google|dfa4ab4b-9dc4-454e-8065-e70c733fa53f\xa2\x01\x0e105.235.139.91\xaa\x01\x02',
            lang.encode("ascii"),
            b'\xb2\x01 1d8ec0240ede109973f3321b9354b44d\xba\x01\x014\xc2\x01\x08Handheld\xca\x01\x10Asus ASUS_I005DA\xea\x01@afcfbf13334be42036e4f742c80b956344bed760ac91b3aff9b607a610ab4390\xf0\x01\x01\xca\x02\nATM Mobils\xd2\x02\x04WIFI\xca\x03 7428b253defc164018c604a1ebbfebdf\xe0\x03\xa8\x81\x02\xe8\x03\xf6\xe5\x01\xf0\x03\xaf\x13\xf8\x03\x84\x07\x80\x04\xe7\xf0\x01\x88\x04\xa8\x81\x02\x90\x04\xe7\xf0\x01\x98\x04\xa8\x81\x02\xc8\x04\x01\xd2\x04=/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/lib/arm\xe0\x04\x01\xea\x04_2087f61c19f57f2af4e7feff0b24d9d9|/data/app/com.dts.freefireth-PdeDnOilCSFn37p1AH_FLg==/base.apk\xf0\x04\x03\xf8\x04\x01\x8a\x05\x0232\x9a\x05\n2019118692\xb2\x05\tOpenGLES2\xb8\x05\xff\x7f\xc0\x05\x04\xe0\x05\xf3F\xea\x05\x07android\xf2\x05pKqsHT5ZLWrYljNb5Vqh//yFRlaPHSO9NWSQsVvOmdhEEn7W+VHNUK+Q+fduA3ptNrGB0Ll0LRz3WW0jOwesLj6aiU7sZ40p8BfUE/FI/jzSTwRe2\xf8\x05\xfb\xe4\x06\x88\x06\x01\x90\x06\x01\x9a\x06\x014\xa2\x06\x014\xb2\x06"GQ@O\x00\x0e^\x00D\x06UA\x0ePM\r\x13hZ\x07T\x06\x0cm\\V\x0ejYV;\x0bU5'
        ]
        payload = b''.join(payload_parts)
        url = "https://loginbp.ggpolarbear.com/MajorLogin" if region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorLogin"
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
        resp = request_retry('POST', url, headers=headers, data=bytes.fromhex(d))
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
        request_retry('POST', url, data=bytes.fromhex(encrypted), headers=headers)
    except: pass

def generate_random_name(name_prefix):
    characters = string.ascii_letters + string.digits
    return name_prefix + ''.join(random.choice(characters) for _ in range(6)).upper()

# ========== RARITY PATTERNS & CHECKERS ==========
PATTERNS = {
    "R4": [r"(\d)\1{3,}", 5],
    "R3": [r"(\d)\1\1(\d)\2\2", 4],
    "S5": [r"(12345|23456|34567|45678|56789)", 6],
    "S4": [r"(0123|1234|2345|3456|4567|5678|6789|9876|8765|7654|6543|5432|4321|3210)", 5],
    "P6": [r"^(\d)(\d)(\d)\3\2\1$", 7],
    "P4": [r"^(\d)(\d)\2\1$", 5],
    "SPH": [r"(69|420|1337|007)", 6],
    "SPM": [r"(100|200|300|400|500|666|777|888|999)", 4],
    "QD": [r"(1111|2222|3333|4444|5555|6666|7777|8888|9999|0000)", 6],
    "MH": [r"^(\d{2,3})\1$", 5],
    "MM": [r"(\d{2})0\1", 4],
    "GD": [r"1618|0618", 5],
    "ULTRA_R4": [r"(\d)\1{5,}", 10],
    "ULTRA_PAL": [r"^(\d)(\d)(\d)\2\1$", 8],
    "ULTRA_MIRROR": [r"^(\d{3})(\d{3})\1$", 9],
    "ULTRA_SEQ": [r"(012345|123456|234567|345678|456789|987654|876543|765432|654321)", 8],
    "ULTRA_QUAD": [r"(\d{4})\1", 8],
    "ULTRA_BINARY": [r"^[01]+$", 7],
    "ULTRA_REPEAT": [r"(\d{2})\1\1", 7],
}

COMPILED_PATTERNS = {}
for ptype, (pattern, points) in PATTERNS.items():
    COMPILED_PATTERNS[ptype] = (re.compile(pattern), points)

def check_rarity(account_data):
    account_id = account_data.get("account_id", "")
    if not account_id or account_id == "N/A":
        return False, None, None, 0
    
    score = 0
    patterns_found = []
    
    for ptype, (pattern, pts) in COMPILED_PATTERNS.items():
        if pattern.search(account_id):
            score += pts
            patterns_found.append(ptype)
    
    digits = [int(d) for d in account_id if d.isdigit()]
    digit_count = len(digits)
    
    if len(set(digits)) == 1 and digit_count >= 4:
        bonus = min(digit_count * 2, 12)
        score += bonus
        patterns_found.append(f"UNIFORM(+{bonus})")
    
    if digit_count >= 4:
        diffs = [digits[i+1] - digits[i] for i in range(len(digits)-1)]
        if len(set(diffs)) == 1:
            bonus = min(abs(diffs[0]) * 2, 10)
            score += bonus
            patterns_found.append(f"ARITHMETIC(+{bonus})")
    
    if len(account_id) <= 8 and account_id.isdigit():
        if int(account_id) < 1000000:
            score += 8
            patterns_found.append("LOW_ID(<1M)")
        elif int(account_id) < 10000000:
            score += 5
            patterns_found.append("LOW_ID(<10M)")
        elif int(account_id) < 100000000:
            score += 3
            patterns_found.append("LOW_ID(<100M)")
    
    if account_id.isdigit() and len(account_id) > 0:
        score += 2
        patterns_found.append("CLEAN_DIGIT")
    
    if len(account_id) >= 3 and account_id == account_id[::-1]:
        score += 6
        patterns_found.append("PALINDROME")
    
    if "888" in account_id or "999" in account_id:
        score += 5
        patterns_found.append("TRIPLE_EIGHT_NINE")
    
    if "0000" in account_id:
        score += 7
        patterns_found.append("QUAD_ZUY")
    
    if len(account_id) >= 4:
        rising = all(digits[i] < digits[i+1] for i in range(len(digits)-1))
        sinking = all(digits[i] > digits[i+1] for i in range(len(digits)-1))
        if rising or sinking:
            bonus = min(len(digits) * 2, 10)
            score += bonus
            patterns_found.append(f"RISING_SINKING(+{bonus})")
    
    if score >= RARITY_SCORE_THRESHOLD:
        if score >= 20:
            rtype = "LEGENDARY"
        elif score >= 16:
            rtype = "MYTHIC"
        elif score >= 12:
            rtype = "EPIC"
        else:
            rtype = "RARE"
        return True, rtype, ",".join(patterns_found[:10]), score
    return False, None, None, score

# ========== GENERATE SINGLE ACCOUNT ==========
def generate_single_account(region, name_prefix, password_prefix):
    account_result = create_account(region, name_prefix, password_prefix)
    if not account_result or account_result.get("account_id", "N/A") == "N/A":
        return None
    is_rare, rtype, reason, rscore = check_rarity(account_result)
    account_result["rarity"] = rtype if is_rare else "NORMAL"
    account_result["rarity_score"] = rscore if is_rare else 0
    account_result["patterns"] = reason.split(",") if is_rare else []
    account_result["rarity_reason"] = reason if is_rare else ""
    return account_result

# ========== FLASK APP ==========
app = Flask(__name__)

# ========== CORS HANDLING ==========
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
    return response

@app.route('/', methods=['GET', 'OPTIONS'])
def index():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    return jsonify({"message": "Free Fire Account Generator API", "endpoint": "/gen?count=5&name=User&password=Pass&region=ID"})

@app.route('/gen', methods=['GET', 'OPTIONS'])
def generate_endpoint():
    if request.method == 'OPTIONS':
        return make_response('', 200)
    
    # Parse query parameters
    count = request.args.get('count', default=1, type=int)
    name = request.args.get('name', default='User', type=str)
    password = request.args.get('password', default='Pass', type=str)
    region = request.args.get('region', default='ID', type=str).upper()

    # Validation
    if count < 1 or count > 100:
        return jsonify({"error": "count must be between 1 and 100"}), 400
    if not name or not password:
        return jsonify({"error": "name and password are required"}), 400
    if region not in REGION_LANG:
        return jsonify({"error": f"invalid region, allowed: {list(REGION_LANG.keys())}"}), 400

    # Generate accounts with concurrency
    max_workers = min(20, count)
    accounts = []
    attempts = 0
    lock = threading.Lock()
    stop_flag = False

    def worker():
        nonlocal attempts, stop_flag
        if stop_flag:
            return
        with lock:
            attempts += 1
        acc = generate_single_account(region, name, password)
        if acc:
            with lock:
                if len(accounts) < count:
                    accounts.append(acc)
                else:
                    stop_flag = True

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker) for _ in range(count * 3)]
        start_time = time.time()
        while len(accounts) < count and time.time() - start_time < 20:
            time.sleep(0.1)
        stop_flag = True
        for f in futures:
            f.cancel()

    response_data = {
        "success": True,
        "total_requested": count,
        "total_created": len(accounts),
        "accounts": accounts,
        "attempts_made": attempts,
    }
    return jsonify(response_data)

# For Vercel, export the app
app = app

if __name__ == "__main__":
    app.run(debug=False)
