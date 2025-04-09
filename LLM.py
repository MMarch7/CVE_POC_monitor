import os
from openai import OpenAI
import msg_push
import logging
import pandas as pd
import requests

github_token = os.environ.get("github_token")
llm_url = os.environ.get("llm_url")
llm_api_key = os.environ.get("llm_api_key")
github_headers = {
    'Authorization': "token {}".format(github_token)
}

def checkEnvData():
    if not github_token:
        logging.error("github_token 获取失败")
        exit(0)
    elif not llm_url:  
        logging.error("LLM_URL获取失败")
        exit(0)
    elif not llm_api_key:  
        logging.error("LLM_API_KEY获取失败")
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
    logging.info("STARTING")
    return

def run_llm_inference(raws):
    client = OpenAI(
        base_url = llm_url,
        api_key = llm_api_key
    )
    
    with open('./utils/prompt.txt', 'r', encoding='utf-8') as f:
        for line in f:  # 逐行处理，不一次性加载
            prompt = line.strip()  # 去掉首尾空白符
    content = requests.get(raws, headers=github_headers).text
    try:
        chat_completion = client.chat.completions.create(
            messages=[
                {
                    "role": "user",
                    "content": prompt+content
                }
            ],
            model = 'deepseek-r1'
        )
    
        text = chat_completion.choices[0].message.content
    except Exception as e:
        if e.code == 20059:
            return "[错误] 输入过长"
    if "No http request" in text:
        return "No http request"
    else:
        return text
    
def main():
    init()
    table_content = msg_push.get_google_sheet("raw")
    df = pd.DataFrame(table_content[1:], columns=table_content[0])
    # 获取HTTP列为空（空字符串、None或NaN）的Link列表
    raws_list = df[df["HTTP"].isin([""]) | df["HTTP"].isna()]["Raw"].tolist()
    for raws in raws_list:
        logging.info(f"开始推送数据包，地址：{raws}")
        if "http" in raws:
            if "\n" in raws:
                raw_list = raws.split("\n")
                packets = [run_llm_inference(raw.strip()) for raw in raw_list]
                packets = "\n".join(packets)
            else:
                packets = run_llm_inference(raws).strip()
        else:
            continue
        if packets:
            msg_push.update_google_sheet("raw", "Raw", raws, "HTTP", packets)
            logging.info(f"推送成功，地址：{raws}，数据包：{packets}")
        else:
            logging.info(f"地址：{raws}，无法生成攻击数据包")


if __name__ == '__main__':
    main()
