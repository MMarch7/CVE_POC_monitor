#!/usr/bin/env python 
# -*- coding: utf-8 -*-
# @Time    : 2025/03/04
# @Author  : LXY
# @File    : main.py
# @Github: https://github.com/MMarch7
import datetime
import feedparser
import logging
import os
#import dingtalkchatbot.chatbot as cb
import requests
import re
import utils.load
from urllib.parse import quote
import msg_push
import csv

github_token = os.environ.get("github_token")
tools_list,keywords,user_list = utils.load.load_tools_list()
CleanKeywords = utils.load.load_clean_list()
known_object = utils.load.load_object_list()

github_headers = {
    'Authorization': "token {}".format(github_token)
}


def checkEnvData():
    if not github_token:
        logging.error("github_token 获取失败")
        exit(0)
    elif not msg_push.tg_token:  
        logging.error("TG_token获取失败")
        exit(0)
    elif not msg_push.wechat_token:  
        logging.error("wechat_token获取失败")
        exit(0)
    elif not msg_push.google_sheet_token:
        logging.error("google_sheet_token获取失败")
        exit(0)
    elif not msg_push.tg_chat_id:
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

def getRSSNews():
    rss_config = utils.load.json_data_load("./RSSs/rss_config.json")
    for key, config in rss_config.items():
        url = config.get("url")
        file_name = config.get("file")
        if url and file_name:
            parse_rss_feed(url,file_name)

def parse_rss_feed(feed_url,file):
    # 解析RSS feed
    try:
        response = requests.get(feed_url,timeout=20)
    except requests.exceptions.SSLError as ssl_err:
        logging.error(f"SSL 错误：无法连接 {feed_url}，跳过该条目。错误信息：{ssl_err}")
        return  # 发生 SSL 错误时跳过当前循环
    except requests.exceptions.RequestException as req_err:
        logging.error(f"请求错误：{feed_url}，错误信息：{req_err}")
        return  # 发生请求错误时跳过当前循环
    except Exception as e:
        logging.error(f"未知错误：{feed_url}，错误信息：{e}")
        return  # 发生其他类型的错误时跳过
    response.encoding = 'utf-8'
    feed_content = response.text
    # 解析RSS feed内容
    feed = feedparser.parse(feed_content)
    if feed.bozo == 1:
        logging.info(file)
        logging.info("解析RSS feed时发生错误:", feed.bozo_exception)
        return
    all_entries = utils.load.json_data_load(f"./RSSs/{file}")
    existing_titles = {entry['title'] for entry in all_entries}
    # 定义一个标志，标记是否输出了新增条目
    new_entries_found = False
    for entry in feed.entries:
        if entry.title not in existing_titles:
            # 输出新增条目
            new_entries_found = True
            all_content_have_cve = True
            logging.info(f"标题: {entry.title}  链接: {entry.link}")
            logging.info("-" * 40)
            if file == "google.json" and 'content' in entry:
                for content in entry.content:
                    if 'cve' not in content['value'].lower():
                        all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
                        break 
            if file == "vulncheck.json" or file == "securityonline.json":
                if "cve" not in entry.title.lower():
                    all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
            if file == "paloalto.json":
                if "medium" in entry.title.lower() or "low" in entry.title.lower():
                    all_content_have_cve = False  # 如果发现某个 content 没有 "CVE"，标记为 False
            all_entries.append({
                    'title': entry.title,
                    'link': entry.link,
                    'published': entry.published
                })
            # 将新增条目添加到新条目列表
            if all_content_have_cve:
                msg = f"标题：{entry.title}\r链接：{entry.link}\r发布时间：{entry.published}"
                logging.info(f"推送到google sheet：{entry.title}  "+entry.link)
                msg_push.send_google_sheet("Emergency Vulnerability","RSS",entry.title,entry.link,"")
    # 如果有新增条目，则更新文件
    if new_entries_found:
        utils.load.json_data_save(f"./RSSs/{file}",all_entries)
    else:
        logging.info(f"{file}未更新新漏洞")

   
def getKeywordNews(keyword):
    cleanKeywords=set(CleanKeywords)
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
                if pushed_at == str(today_date) and keyword_name not in cleanKeywords:
                    msg_push.send_google_sheet("CVE",keyword,keyword_name,keyword_url,description)
                    today_keyword_info_tmp.append({"keyword_name": keyword_name, "keyword_url": keyword_url, "pushed_at": pushed_at,"description":description})

                    logging.info("[+] keyword: {} \n 项目名称：{} \n项目地址：{}\n推送时间：{}\n描述：{}".format(keyword, keyword_name,keyword_url,pushed_at,description))
                else:
                    logging.info("[-] keyword: {} ,{}的更新时间为{}, 不属于今天".format(keyword, keyword_name, pushed_at))
            except Exception as e:
                pass
    except Exception as e:
        logging.error("Error occurred: %s, github链接不通", e) 
    return today_keyword_info_tmp
    
def getCVE_PoCs():
    #通过关键词检索PoC
    clean_add = []
    pushdata=list()
    for keyword in keywords:
        templist=getKeywordNews(keyword)
        for tempdata in templist:
            pushdata.append(tempdata)
            clean_add.append(tempdata.get("keyword_name"))
    msg_push.keyword_msg(pushdata)
    if clean_add:
        utils.load.flash_clean_list(clean_add)

def getCISANews():
    with open('./utils/CISA.txt', 'r') as file:
        txt_content = file.read().splitlines()
    url = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv'
    # 读取 CSV 内容
    try:
        response = requests.get(url)
    except Exception as e:
        # 捕获其他可能的异常
        logging.info(f"An unexpected error occurred: {e}")
        return
    response.raise_for_status()  # 检查请求是否成功
    data = response.text  # 获取 CSV 文件内容
    reader = csv.DictReader(data.splitlines())
    msg = ""
    new_cve_list = []
    for row in reader:
        cve = row['cveID']  # 假设 'cveID' 是 CSV 中的列名
        if cve not in txt_content:
            name = row['vulnerabilityName'] + "(" + cve + ")"
            name_cn = utils.load.baidu_api(name)
            shortDescription = row['shortDescription']
            knownRansomwareCampaignUse = row['knownRansomwareCampaignUse']
            shortDescription_cn = utils.load.baidu_api(shortDescription)
            notes = row['notes']
            info = f"名称：{name_cn}\r\n描述：{shortDescription_cn}\r\n是否被勒索利用：{knownRansomwareCampaignUse}\r\n链接：{notes}"
            if not msg:
                msg = "美国网络安全局漏洞推送：\r\n" + info
            else:
                msg += "\r\n\r\n" + info
            new_cve_list.append(cve)
    
    if new_cve_list:
        logging.info("企微推送CISA漏洞更新："  + ", ".join(new_cve_list))
        msg_push.tg_push(msg)
        with open("./utils/CISA.txt", 'a') as file:
            for cve in new_cve_list:
                file.write(f"{cve}\n")
    else:
        logging.info("CISA未更新漏洞")

def main():
    init()
    #紧急漏洞RSS推送
    getRSSNews()
    #紧急漏洞CISA推送
    getCISANews()
    #CVE披露PoC获取
    getCVE_PoCs()

    return


if __name__ == '__main__':
    main()
