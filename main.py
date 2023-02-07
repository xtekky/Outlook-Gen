from tls_client   import Session
from re           import findall
from json         import loads, dumps, load
from datetime     import datetime
from utils.crypto import Crypto
from utils.solver import Funcaptcha
from random       import randint, choice
from names        import get_first_name, get_last_name
from os           import urandom
from time         import time
from threading    import Thread

class Outlook:
    def __init__(this, proxy: str = None):
        this.client          = Session(client_identifier='chrome_108')
        this.client.proxies  = {'http' : f'http://{proxy}','https': f'http://{proxy}'} if proxy else None
        
        this.Key             = None
        this.randomNum       = None
        this.SKI             = None
        this.uaid            = None
        this.tcxt            = None
        this.apiCanary       = None
        this.encAttemptToken = ""
        this.dfpRequestId    = ""

        this.siteKey         = 'B7D8911C-5CC8-A9A3-35B0-554ACEE604DA'
        this.userAgent       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
        
        this.__start__       = this.__init_client()
        this.account_info    = this.__account_info()
        
        this.cipher          = Crypto.encrypt(this.account_info['password'], this.randomNum, this.Key)
    

    @staticmethod
    def log(message: str):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")
        
    def __init_client(this):
        content = this.client.get('https://signup.live.com/signup?lic=1', headers = {
            "host"            : "signup.live.com",
            "accept"          : "*/*",
            "accept-encoding" : "gzip, deflate, br",
            "connection"      : "keep-alive",
            "user-agent"      : this.userAgent
        })
        
        this.Key, this.randomNum, this.SKI = findall(r'Key="(.*?)"; var randomNum="(.*?)"; var SKI="(.*?)"', content.text)[0]
        json_data = loads(findall(r't0=([\s\S]*)w\["\$Config"]=', content.text)[0].replace(';', ''))
        
        this.uaid       = json_data['clientTelemetry']['uaid']
        this.tcxt       = json_data['clientTelemetry']['tcxt']
        this.apiCanary  = json_data['apiCanary']
    
    def __handle_error(this, code: str) -> str:
        errors = {
            "403" : "Bad Username",
            "1040": "SMS Needed",
            "1041": "Enforcement Captcha",
            "1042": "Text Captcha",
            "1043": "Invalid Captcha",
            "1312": "Captcha Error",
            "450" : "Daily Limit Reached",
            "1304": "OTP Invalid",
            "1324": "Verification SLT Invalid",
            "1058": "Username Taken",
            "1117": "Domain Blocked",
            "1181": "Reserved Domain",
            "1002": "Incorrect Password",
            "1009": "Password Conflict",
            "1062": "Invalid Email Format",
            "1063": "Invalid Phone Format",
            "1039": "Invalid Birth Date",
            "1243": "Invalid Gender",
            "1240": "Invalid first name",
            "1241": "Invalid last name",
            "1204": "Maximum OTPs reached",
            "1217": "Banned Password",
            "1246": "Proof Already Exists",
            "1184": "Domain Blocked",
            "1185": "Domain Blocked",
            "1052": "Email Taken",
            "1242": "Phone Number Taken",
            "1220": "Signup Blocked",
            "1064": "Invalid Member Name Format",
            "1330": "Password Required",
            "1256": "Invalid Email",
            "1334": "Eviction Warning Required",
            "100" : "Bad Register Request"
        }
        
        return errors[code]
    
    def __account_info(this) -> dict:
        
        token      = urandom(3).hex()
        first_name = get_first_name()
        last_name  = get_last_name()
        email      = f"{first_name}.{last_name}.{token}@outlook.com".lower()
        password   = email.encode('utf-8').hex() + ':Tek01'
        
        return {
            "password"          : password,
            "CheckAvailStateMap": [
                f"{email}:undefined"
            ],
            "MemberName": email,
            "FirstName" : first_name,
            "LastName"  : last_name,
            "BirthDate" : f"{randint(1, 27)}:0{randint(1, 9)}:{randint(1969, 2000)}"
        }
        
    def __base_headers(this):
        return {
            "accept"            : "application/json",
            "accept-encoding"   : "gzip, deflate, br",
            "accept-language"   : "en-US,en;q=0.9",
            "cache-control"     : "no-cache",
            "canary"            : this.apiCanary,
            "content-type"      : "application/json",
            "dnt"               : "1",
            "hpgid"             : f"2006{randint(10, 99)}",
            "origin"            : "https://signup.live.com",
            "pragma"            : "no-cache",
            "scid"              : "100118",
            "sec-ch-ua"         : '" Not A;Brand";v="107", "Chromium";v="96", "Google Chrome";v="96"',
            "sec-ch-ua-mobile"  : "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest"    : "empty",
            "sec-fetch-mode"    : "cors",
            "sec-fetch-site"    : "same-origin",
            "tcxt"              : this.tcxt,
            "uaid"              : this.uaid,
            "uiflvr"            : "1001",
            "user-agent"        : this.userAgent,
            "x-ms-apitransport" : "xhr",
            "x-ms-apiversion"   : "2",
            "referrer"          : "https://signup.live.com/?lic=1"
        }
    
    def __base_payload(this, captcha_solved: bool) -> dict:
        payload = {
            **this.account_info,
            "RequestTimeStamp"          : str(datetime.now()).replace(" ", "T")[:-3] + "Z",
            "EvictionWarningShown"      : [],
            "UpgradeFlowToken"          : {},
            "MemberNameChangeCount"     : 1,
            "MemberNameAvailableCount"  : 1,
            "MemberNameUnavailableCount": 0,
            "CipherValue"               : this.cipher,
            "SKI"                       : this.SKI,
            "Country"                   : "CA",
            "AltEmail"                  : None,
            "IsOptOutEmailDefault"      : True,
            "IsOptOutEmailShown"        : True,
            "IsOptOutEmail"             : True,
            "LW"                        : True,
            "SiteId"                    : 68692,
            "IsRDM"                     : 0,
            "WReply"                    : None,
            "ReturnUrl"                 : None,
            "SignupReturnUrl"           : None,
            "uiflvr"                    : 1001,
            "uaid"                      : this.uaid,
            "SuggestedAccountType"      : "OUTLOOK",
            "SuggestionType"            : "Locked",
            "encAttemptToken"           : this.encAttemptToken,
            "dfpRequestId"              : this.dfpRequestId,
            "scid"                      : 100118,
            "hpgid"                     : 201040,
        }
        
        if captcha_solved:
            cap_token = Funcaptcha.getKey()
            Outlook.log(f'solved captcha: [{cap_token[:100]}...]')
            
            payload.update({
                "HType" : "enforcement",
                "HSol"  : cap_token,
                "HPId"  : this.siteKey,
            })
        
        return payload

    def register_account(this, captcha_solved: bool = False) -> (dict and str):
        
        try:
            for _ in range(3):
                try:
                    response = this.client.post('https://signup.live.com/API/CreateAccount?lic=1',
                            json = this.__base_payload(captcha_solved), headers = this.__base_headers())
                    
                    Outlook.log(f'register resp:  [{str(response.json())[:100]}...]'); break
                
                except Exception as e:
                    Outlook.log(f'http error: [{e}]')
                    continue

            error = response.json().get("error")
            if error:
                code = error.get("code")
                if '1041' in code:
                    error_data  = loads(error.get("data"))
                    
                    this.encAttemptToken = error_data['encAttemptToken']
                    this.dfpRequestId    = error_data['dfpRequestId']
                    
                    return this.register_account(True)
                
                else:
                    return {}, this.__handle_error(code)
            
            else:
                return this.account_info, 'Success'
            
        except Exception as e:
            return {}, str(e)

def register_loop(proxies: list):
    while True:
        start           = time()
        outlook         = Outlook(choice(proxies))
        account, status = outlook.register_account()
        stop            = time() - start

        if status == 'Success':
            Outlook.log(f'registered acc: [{account["MemberName"]}:...] {round(stop, 2)}s')
            with open('./data/accounts.txt', 'a') as f:
                f.write(f'{account["MemberName"]}:{account["password"]}\n')
        else:
            Outlook.log(f'register error: [{status}] {round(stop, 2)}s')

if __name__ == "__main__":
    proxies = open('./data/proxies.txt').read().splitlines()
    config  = load(open('./data/config.json'))
    
    for _ in range(config['threads']):
        Thread(target = register_loop, args = (proxies,)).start()
