import requests
import time
import hmac
import urllib.parse
import hashlib
import base64
import json
import smtplib
from email.mime.text import MIMEText
from email.header import Header

### Start of SMTP Send Email

mail_host="smtp.qq.com"  # 设置服务器
mail_user="username"     # 用户名
mail_pass="password"     # 口令 
receivers = ['xxx@xxx.com']  # 接收邮箱

def send_email(title, content):
    try:
        smtpObj = smtplib.SMTP() 
        smtpObj.connect(mail_host, 25)    # 25 为 SMTP 端口号
        smtpObj.login(mail_user,mail_pass)
        message = MIMEText(title, 'plain', 'utf-8')
        message['From'] = Header("LazyCrasher", 'utf-8')
        message['To'] =  Header("", 'utf-8')
        
        message['Subject'] = Header(content, 'utf-8')
        smtpObj.sendmail(mail_user, receivers, message.as_string())
    except smtplib.SMTPException:
        print ("Error: 邮件发送失败")

### End of SMTP Send Email

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
    # send_bark("test")
    # test send_email
    send_email("Test", "测试内容")