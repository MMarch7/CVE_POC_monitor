import logging
import requests
import os
import json
import datetime
import telebot

wechat_token = os.environ.get("wechat_token")
google_sheet_token = os.environ.get("google_sheet_token")
tg_chat_id = os.environ.get("tg_chat_id")
tg_token = os.environ.get("tg_token")
WEBHOOK_URL = f"https://script.google.com/macros/s/{google_sheet_token}/exec"
google_sheet_headers = {
    'Content-Type': 'application/json'
}

current_date = datetime.date.today().strftime('%Y-%m-%d  %H:%M') 

def send_google_sheet(sheet,keyword,name,url,description):
    data = {
        "action": "insert",
        "sheet_name":sheet,
        "时间":current_date,
        "关键词": keyword,
        "项目名称": name,
        "项目地址":url,
        "项目描述":description
    }
    response = requests.post(WEBHOOK_URL,headers=google_sheet_headers,data=json.dumps(data))
    if "success" not in response.text:
        logging.error(f"推送google_sheet失败，报错如下：{response.text}")

def get_google_sheet(sheet):
    response = requests.get(WEBHOOK_URL,headers=google_sheet_headers,params={"sheet":sheet})
    # 解析JSON
    parsed_data = json.loads(response.text)
    # 提取字段
    status_code = parsed_data["code"]      # 状态码（200）
    table_content = parsed_data["data"]    # 表的全部内容（二维列表）
    if status_code != 200:
        logging.error(f"获取google_sheet失败，报错如下：{response.text}")
        exit(0)
    else:
        return table_content

def send_google_raw(sheet,link,Raw):
    data = {
        "action": "insert",
        "时间":current_date,
        "sheet_name":sheet,
        "Link": link,
        "Raw": Raw
    }
    response = requests.post(WEBHOOK_URL,headers=google_sheet_headers,data=json.dumps(data))
    if "success" not in response.text:
        logging.error(f"推送google_sheet失败，报错如下：{response.text}")

def update_google_sheet(sheetName,searchField,searchValue,targetField,newValue):
    data = {
        "action": "update",
        "sheetName":sheetName,
        "searchField":searchField,
        "searchValue": searchValue,
        "targetField": targetField,
        "newValue":newValue
    }
    response = requests.post(WEBHOOK_URL,headers=google_sheet_headers,data=json.dumps(data))
    if "success" not in response.text:
        logging.error(f"推送google_sheet失败，报错如下：{response.text}")

def send_google_sheet_githubVul(sheet,keyword,name,cve,url,description):
    data = {
        "action": "insert",
        "sheet_name":sheet,
        "时间":current_date,
        "关键词": keyword,
        "名称": name,
        "编号":cve,
        "地址":url,
        "描述":description
    }
    response = requests.post(WEBHOOK_URL,headers=google_sheet_headers,data=json.dumps(data))
    if "success" not in response.text:
        logging.error(f"推送google_sheet失败，报错如下：{response.text}")

def keyword_msg(pushdata):
    text=""
    for data in pushdata:
        text+="名称:{}\n地址:{}\n详情:{}\n\n\n ".format(data.get("keyword_name"),data.get("keyword_url"),data.get("description"))
    if text:
        tg_push(text)
        logging.info("消息发送完成")
    else:
        logging.info("当前时段未发现新信息")

def tg_push(text):
    tb = telebot.TeleBot(tg_token)
    max_length = 4000
    for i in range(0, len(text), max_length):
        chunk = text[i:i + max_length]
        tb.send_message(tg_chat_id, chunk)
    
def wechat_push(msg):
    url = f'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={wechat_token}'
    # 请求头
    header = {
        'Content-Type': 'application/json'
    }
    # 请求数据
    data = {
        "msgtype": "text",
        "text": {
            "content": msg
        }
    }
    response = requests.post(url, headers=header, data=json.dumps(data))
    logging.info("企微订阅推送  " + str(response.status_code))
