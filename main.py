#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2025/03/04
# @Author  : LXY
# @File    : main.py
# @Github: https://github.com/MMarch7
from datetime import datetime
import logging
import os
#import dingtalkchatbot.chatbot as cb
import requests
import re
import utils.yaml_load
import telebot
from urllib.parse import quote
import json

github_token = os.environ.get("github_token")
google_sheet_token = os.environ.get("google_sheet_token")
tg_chat_id = os.environ.get("tg_chat_id")
tg_token = os.environ.get("tg_token")
WEBHOOK_URL = f"https://script.google.com/macros/s/{google_sheet_token}/exec"

current_date = datetime.today().strftime('%Y-%m-%d') 

tools_list,keywords,user_list = utils.yaml_load.load_tools_list()
CleanKeywords = utils.yaml_load.load_clean_list()

github_headers = {
    'Authorization': "token {}".format(github_token)
}
google_sheet_headers = {
    'Content-Type': 'application/json'
}

def checkEnvData():
    if not github_token:
        logging.error("github_token 获取失败")
        exit(0)
    elif not tg_token:
        logging.error("TG_token获取失败")
        exit(0)
    elif not google_sheet_token:
        logging.error("google_sheet_token获取失败")
        exit(0)
    elif not tg_chat_id:
        logging.error("tg_chat_id获取失败")
        exit(0)
    else:
        logging.info("环境变量加载成功")


def init():
    logging.basicConfig(level=logging.INFO)
    logging.info("init application")
    checkEnvData()
    logging.info("start send test msg")
    return



def getKeywordNews(keyword):
    today_keyword_info_tmp=[]
    try:
        # 抓取本年的
        #keyword = quote(keyword)
        logging.info(keyword)
        api = "https://api.github.com/search/repositories?q={}&sort=updated".format(keyword)
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()
        n=20 if len(json_str['items'])>20 else len(json_str['items'])
        for i in range(0, n):
            keyword_url = json_str['items'][i]['html_url']
            try:
                keyword_name = json_str['items'][i]['name']
                description = json_str['items'][i]['description']
                pushed_at_tmp = json_str['items'][i]['pushed_at']
                pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]
                if pushed_at == str(today_date):
                    send_google_sheet("CVE",keyword,keyword_name,keyword_url,description)
                    today_keyword_info_tmp.append({"keyword_name": keyword_name, "keyword_url": keyword_url, "pushed_at": pushed_at,"description":description})

                    logging.info("[+] keyword: {} \n 项目名称：{} \n项目地址：{}\n推送时间：{}\n描述：{}".format(keyword, keyword_name,keyword_url,pushed_at,description))
                else:
                    logging.info("[-] keyword: {} ,{}的更新时间为{}, 不属于今天".format(keyword, keyword_name, pushed_at))
            except Exception as e:
                pass
    except Exception as e:
        logging.error(e, "github链接不通")
    return today_keyword_info_tmp
    
def send_google_sheet(sheet,keyword,name,url,description):
    data = {
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

def sendmsg(pushdata):
    text=""
    for data in pushdata:
        text+="名称:{}\n地址:{}\n详情:{}\n\n\n ".format(data.get("keyword_name"),data.get("keyword_url"),data.get("description"))
    if text:
        base_keywords.google_sheet_push(pushdata)
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
    

def main():
    init()
    cleanKeywords=set(CleanKeywords)
    pushdata=list()

    for keyword in keywords:
        templist=getKeywordNews(keyword)
        for tempdata in templist:
            if tempdata.get("keyword_name") in cleanKeywords:
                pass
            else:
                pushdata.append(tempdata)
                cleanKeywords.add(tempdata.get("keyword_name"))
    sendmsg(pushdata)
    utils.yaml_load.flash_clean_list(list(cleanKeywords))
    return

def test():
    # getKeywordNews("漏洞")
    init()

if __name__ == '__main__':
    main()
