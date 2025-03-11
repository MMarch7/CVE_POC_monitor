from datetime import datetime
import requests
import logging
import json

WEBHOOK_URL = "https://script.google.com/macros/s/AKfycbxNqyC0KymxoBWVMPqxzJ2k8V0oP3QDeJoDSU2CdB_B5B7fozK6E3tc4-oeIuEUa4RF/exec"
current_date = datetime.today().strftime('%Y-%m-%d')
headers = {
    'Content-Type': 'application/json'
}
def google_sheet_push(pushdata):
    for data in pushdata:
        content = {
            "sheet_name":"CVE",
            "时间":current_date,
            "项目名称":data.get("keyword_name"),
            "项目地址":data.get("keyword_url"),
            "项目描述":data.get("description"),
            "关键词":data.get("keyword")
        }
        response = requests.post(WEBHOOK_URL, headers=headers, data=json.dumps(content))
        if "success" not in response.text:
            logging.error(f"推送Google Sheet失败，报错信息如下：\n{response.text}")
    

    