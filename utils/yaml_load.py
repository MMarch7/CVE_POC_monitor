import yaml
import logging

 #读取配置文件
def load_config():
    with open('./utils/config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
        #github_token = config['all_config']['github_token']
        if int(config['all_config']['wechat'][0]['enable']) == 1:
            webhook = config['all_config']['wechat'][1]['webhook']
            app_name = config['all_config']['wechat'][3]['app_name']
            return app_name,webhook
        elif int(config['all_config']['tgbot'][0]['enable']) ==1 :
            tgbot_token = config['all_config']['tgbot'][1]['token']
            tgbot_group_id = config['all_config']['tgbot'][2]['group_id']
            app_name = config['all_config']['tgbot'][3]['app_name']
            return app_name,tgbot_token,tgbot_group_id
        elif int(config['all_config']['tgbot'][0]['enable']) == 0 and int(config['all_config']['feishu'][0]['enable']) == 0 and int(config['all_config']['server'][0]['enable']) == 0 and int(config['all_config']['pushplus'][0]['enable']) == 0 and int(config['all_config']['dingding'][0]['enable']) == 0:
            logging.error("[-] 配置文件有误, 社交软件的enable不能为0")

def load_tools_list():
    with open('./utils/monitor_list.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['tools_list'], list['keyword_list'], list['user_list']
    
def load_clean_list():
    with open('./utils/clean.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['clean_list']
    
def flash_clean_list(clean_list):
    with open("./utils/clean.yaml", "w",encoding="utf-8") as file:
        yaml.dump({"clean_list": clean_list}, file, default_flow_style=False)
