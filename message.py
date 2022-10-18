import requests
import time
import hmac
import urllib.parse
import hashlib
import base64
import json

### Start of Bark

def send_bark(title, content):
    token = ""
    url = f"https://api.day.app/{token}/{title}/{content}"
    requests.get(url=url)

### End of Bark


### Start of DingTalk Bot

dingUrl = "https://oapi.dingtalk.com/robot/send?access_token={}&timestamp={}&sign={}"
secret = ''
access_token = ''

def get_sign(timestamp):
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return sign

def send_dingtalk(title, content):
    timestamp = str(round(time.time() * 1000))
    sign = get_sign(timestamp)
    headers = {
        "Content-Type": "application/json;charset=utf-8"
    }
    data = {
        "msgtype": "markdown",
        "markdown": {
            "title": title,
            "content": content
        }
    }
    requests.post(url=dingUrl.format(access_token, timestamp, sign), headers=headers, data=json.dumps(data))

### End of DingTalk Bot


if __name__ == '__main__':
    # test send_bark
    send_bark("test")