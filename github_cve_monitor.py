#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : yhy&ddm&w4ter

# 每3分钟检测一次githu
# 是否有新的cve漏洞提交记录，若有则通过server酱和钉钉机器人推送,飞书捷径推送（二者配置一个即可）
# 建议使用screen命令运行在自己的linux vps后台上，就可以愉快的接收各种cve了
# https://my.oschina.net/u/4581868/blog/4380482
# https://github.com/kiang70/Github-Monitor
import json
from collections import OrderedDict
import requests, time, re
import dingtalkchatbot.chatbot as cb
import datetime
import hashlib
import yaml
from lxml import etree
import sqlite3


#读取配置文件
def load_config():
    with open('config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.load(f,Loader=yaml.FullLoader)
        github_token = config['all_config']['github_token']
        translate = False
        if int(config['all_config']['translate'][0]['enable']) == 1:
            translate = True
        if int(config['all_config']['dingding'][0]['enable']) == 1:
            dingding_webhook = config['all_config']['dingding'][1]['webhook']
            dingding_secretKey = config['all_config']['dingding'][2]['secretKey']
            app_name = config['all_config']['dingding'][3]['app_name']
            return app_name,github_token,dingding_webhook,dingding_secretKey, translate
        elif int(config['all_config']['feishu'][0]['enable']) == 1:
            feishu_webhook = config['all_config']['feishu'][1]['webhook']
            app_name = config['all_config']['feishu'][2]['app_name']
            return app_name,github_token,feishu_webhook,feishu_webhook, translate
        elif int(config['all_config']['server'][0]['enable']) == 1:
            server_sckey = config['all_config']['server'][1]['sckey']
            app_name = config['all_config']['server'][2]['app_name']
            return app_name,github_token,server_sckey, translate
        elif int(config['all_config']['pushplus'][0]['enable']) == 1:
            pushplus_token = config['all_config']['pushplus'][1]['token']
            app_name = config['all_config']['pushplus'][2]['app_name']
            return app_name,github_token,pushplus_token, translate
        elif int(config['all_config']['tgbot'][0]['enable']) ==1 :
            tgbot_token = config['all_config']['tgbot'][1]['token']
            tgbot_group_id = config['all_config']['tgbot'][2]['group_id']
            app_name = config['all_config']['tgbot'][3]['app_name']
            return app_name,github_token,tgbot_token,tgbot_group_id, translate
        elif int(config['all_config']['tgbot'][0]['enable']) == 0 and int(config['all_config']['feishu'][0]['enable']) == 0 and int(config['all_config']['server'][0]['enable']) == 0 and int(config['all_config']['pushplus'][0]['enable']) == 0 and int(config['all_config']['dingding'][0]['enable']) == 0:
            print("[-] 配置文件有误, 五个社交软件的enable不能为0")

github_headers = {
    'Authorization': "token {}".format(load_config()[1])
}

#读取黑名单用户
def black_user():
    with open('config.yaml', 'r', encoding='utf-8') as f:
        config = yaml.load(f, Loader=yaml.FullLoader)
        black_user = config['all_config']['black_user']
        return black_user

#初始化创建数据库
def create_database():
    conn = sqlite3.connect('data.db')
    # print("[]create_database 函数 连接数据库成功！")
    # logging.info("create_database 函数 连接数据库成功！")
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE IF NOT EXISTS cve_monitor
                   (cve_name varchar(255),
                    pushed_at varchar(255),
                    cve_url varchar(255));''')
        print("成功创建CVE监控表")
        cur.execute('''CREATE TABLE IF NOT EXISTS keyword_monitor
                   (keyword_name varchar(255),
                    pushed_at varchar(255),
                    keyword_url varchar(255));''')
        print("成功创建关键字监控表")
        cur.execute('''CREATE TABLE IF NOT EXISTS redteam_tools_monitor
                   (tools_name varchar(255),
                    pushed_at varchar(255),
                    tag_name varchar(255));''')
        print("成功创建红队工具监控表")
        cur.execute('''CREATE TABLE IF NOT EXISTS user_monitor
                   (repo_name varchar(255));''')
        print("成功创建大佬仓库监控表")
    except Exception as e:
        print("创建监控表失败！报错：{}".format(e))
    conn.commit()  # 数据库存储在硬盘上需要commit  存储在内存中的数据库不需要
    conn.close()
    if load_config()[0] == "dingding":
        dingding("test", "连接成功", load_config()[2], load_config()[3])
    elif load_config()[0] == "server":
        server("test", "连接成功", load_config()[2])
    elif load_config()[0] == "pushplus":
        pushplus("test", "连接成功", load_config()[2])        
    elif load_config()[0] == "tgbot":
        tgbot("test", "连接成功", load_config()[2], load_config()[3])
#根据排序获取本年前20条CVE
def getNews():
    today_cve_info_tmp = []
    try:
        # 抓取本年的
        year = datetime.datetime.now().year
        api = "https://api.github.com/search/repositories?q=CVE-{}&sort=updated".format(year)
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        # cve_total_count = json_str['total_count']
        # cve_description = json_str['items'][0]['description']
        today_date = datetime.date.today()
        n = len(json_str['items'])
        if n > 20:
            n = 20
        for i in range(0, n):
            cve_url = json_str['items'][i]['html_url']
            if cve_url.split("/")[-2] not in black_user():
                try:
                    cve_name_tmp = json_str['items'][i]['name'].upper()
                    cve_name = re.findall('(CVE\-\d+\-\d+)', cve_name_tmp)[0].upper()
                    pushed_at_tmp = json_str['items'][i]['created_at']
                    pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]
                    if pushed_at == str(today_date):
                        today_cve_info_tmp.append({"cve_name": cve_name, "cve_url": cve_url, "pushed_at": pushed_at})
                    else:
                        print("[-] 该{}的更新时间为{}, 不属于今天的CVE".format(cve_name, pushed_at))
                except Exception as e:
                    pass
            else:
                pass
        today_cve_info = OrderedDict()
        for item in today_cve_info_tmp:
            today_cve_info.setdefault(item['cve_name'], {**item, })
        today_cve_info = list(today_cve_info.values())

        return today_cve_info
        # return cve_total_count, cve_description, cve_url, cve_name
        #\d{4}-\d{2}-\d{2}

    except Exception as e:
        print(e, "github链接不通")
        return '', '', ''

def getKeywordNews(keyword):
    today_keyword_info_tmp = []
    try:
        # 抓取本年的
        api = "https://api.github.com/search/repositories?q={}&sort=updated".format(keyword)
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()
        n = len(json_str['items'])
        if n > 20:
            n = 20
        for i in range(0, n):
            keyword_url = json_str['items'][i]['html_url']
            if keyword_url.split("/")[-2] not in black_user():
                try:
                    keyword_name = json_str['items'][i]['name']
                    pushed_at_tmp = json_str['items'][i]['created_at']
                    pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0]
                    if pushed_at == str(today_date):
                        today_keyword_info_tmp.append({"keyword_name": keyword_name, "keyword_url": keyword_url, "pushed_at": pushed_at})
                        print("[+] keyword: {} ,{}".format(keyword, keyword_name))
                    else:
                        print("[-] keyword: {} ,该{}的更新时间为{}, 不属于今天".format(keyword, keyword_name, pushed_at))
                except Exception as e:
                    pass
            else:
                pass
        today_keyword_info = OrderedDict()
        for item in today_keyword_info_tmp:
            today_keyword_info.setdefault(item['keyword_name'], {**item, })
        today_keyword_info = list(today_keyword_info.values())

        return today_keyword_info

    except Exception as e:
        print(e, "github链接不通")
    return today_keyword_info_tmp

#获取到的关键字仓库信息插入到数据库
def keyword_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("keyword_insert_into_sqlite3 函数 打开数据库成功！")
    print(data)
    cur = conn.cursor()
    for i in range(len(data)):
        try:
            keyword_name = data[i]['keyword_name']
            cur.execute("INSERT INTO keyword_monitor (keyword_name,pushed_at,keyword_url) VALUES ('{}', '{}', '{}')".format(keyword_name, data[i]['pushed_at'], data[i]['keyword_url']))
            print("keyword_insert_into_sqlite3 函数: {}插入数据成功！".format(keyword_name))
        except Exception as e:
            print("keyword_insert_into_sqlite3 error {}".format(e))
            pass
    conn.commit()
    conn.close()
#查询数据库里是否存在该关键字仓库的方法
def query_keyword_info_database(keyword_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT keyword_name FROM keyword_monitor WHERE keyword_name = '{}';".format(keyword_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))

#获取不存在数据库里的关键字信息
def get_today_keyword_info(today_keyword_info_data):
    today_all_keyword_info = []
    for i in range(len(today_keyword_info_data)):
        try:
            today_keyword_name = today_keyword_info_data[i]['keyword_name']
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_keyword_info_data[i]['keyword_name'].upper())
            # 如果仓库名字带有 cve-xxx-xxx, 先查询看看 cve 监控中是否存在, 防止重复推送
            if len(today_cve_name) > 0 and query_cve_info_database(today_cve_name.upper()) == 1: 
                pass
            Verify = query_keyword_info_database(today_keyword_name)
            if Verify == 0:
                print("[+] 数据库里不存在{}".format(today_keyword_name))
                today_all_keyword_info.append(today_keyword_info_data[i])
            else:
                print("[-] 数据库里存在{}".format(today_keyword_name))
        except Exception as e:
            pass
    return today_all_keyword_info


#获取到的CVE信息插入到数据库
def cve_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("cve_insert_into_sqlite3 函数 打开数据库成功！")
    cur = conn.cursor()
    for i in range(len(data)):
        try:
            cve_name = re.findall('(CVE\-\d+\-\d+)', data[i]['cve_name'])[0].upper()
            cur.execute("INSERT INTO cve_monitor (cve_name,pushed_at,cve_url) VALUES ('{}', '{}', '{}')".format(cve_name, data[i]['pushed_at'], data[i]['cve_url']))
            print("cve_insert_into_sqlite3 函数: {}插入数据成功！".format(cve_name))
        except Exception as e:
            pass
    conn.commit()
    conn.close()
#查询数据库里是否存在该CVE的方法
def query_cve_info_database(cve_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT cve_name FROM cve_monitor WHERE cve_name = '{}';".format(cve_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))
#查询数据库里是否存在该tools工具名字的方法
def query_tools_info_database(tools_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT tools_name FROM redteam_tools_monitor WHERE tools_name = '{}';".format(tools_name)
    cursor = cur.execute(sql_grammar)
    return len(list(cursor))
#获取不存在数据库里的CVE信息
def get_today_cve_info(today_cve_info_data):
    today_all_cve_info = []
    # today_cve_info_data = getNews()
    for i in range(len(today_cve_info_data)):
        try:
            today_cve_name = re.findall('(CVE\-\d+\-\d+)', today_cve_info_data[i]['cve_name'])[0].upper()
            if exist_cve(today_cve_name) == 1:
                Verify = query_cve_info_database(today_cve_name.upper())
                if Verify == 0:
                    print("[+] 数据库里不存在{}".format(today_cve_name.upper()))
                    today_all_cve_info.append(today_cve_info_data[i])
                else:
                    print("[-] 数据库里存在{}".format(today_cve_name.upper()))
        except Exception as e:
            pass
    return today_all_cve_info
#获取红队工具信息插入到数据库
def tools_insert_into_sqlite3(data):
    conn = sqlite3.connect('data.db')
    print("tools_insert_into_sqlite3 函数 打开数据库成功！")
    cur = conn.cursor()
    for i in range(len(data)):
        Verify = query_tools_info_database(data[i]['tools_name'])
        if Verify == 0:
            print("[+] 红队工具表数据库里不存在{}".format(data[i]['tools_name']))
            cur.execute("INSERT INTO redteam_tools_monitor (tools_name,pushed_at,tag_name) VALUES ('{}', '{}','{}')".format(data[i]['tools_name'], data[i]['pushed_at'], data[i]['tag_name']))
            print("tools_insert_into_sqlite3 函数: {}插入数据成功！".format(format(data[i]['tools_name'])))
        else:
            print("[-] 红队工具表数据库里存在{}".format(data[i]['tools_name']))
    conn.commit()
    conn.close()
#读取本地红队工具链接文件转换成list
def load_tools_list():
    with open('tools_list.yaml', 'r',  encoding='utf-8') as f:
        list = yaml.load(f,Loader=yaml.FullLoader)
        return list['tools_list'], list['keyword_list'], list['user_list']
#获取红队工具的名称，更新时间，版本名称信息
def get_pushed_at_time(tools_list):
    tools_info_list = []
    for url in tools_list:
        try:
            tools_json = requests.get(url, headers=github_headers, timeout=10).json()
            pushed_at_tmp = tools_json['pushed_at']
            pushed_at = re.findall('\d{4}-\d{2}-\d{2}', pushed_at_tmp)[0] #获取的是API上的时间
            tools_name = tools_json['name']
            api_url = tools_json['url']
            try:
                releases_json = requests.get(url+"/releases", headers=github_headers, timeout=10).json()
                tag_name = releases_json[0]['tag_name']
            except Exception as e:
                tag_name = "no releases"
            tools_info_list.append({"tools_name":tools_name,"pushed_at":pushed_at,"api_url":api_url,"tag_name":tag_name})
        except Exception as e:
            print("get_pushed_at_time ", e)
            pass

    return tools_info_list
#根据红队名名称查询数据库红队工具的更新时间以及版本名称并返回
def tools_query_sqlite3(tools_name):
    result_list = []
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT pushed_at,tag_name FROM redteam_tools_monitor WHERE tools_name = '{}';".format(tools_name)
    cursor = cur.execute(sql_grammar)
    for result in cursor:
        result_list.append({"pushed_at":result[0],"tag_name":result[1]})
    conn.close()
    print("[###########]  tools_query_sqlite3 函数内 result_list 的值 为 - > {}".format(result_list))
    return result_list
#获取更新了的红队工具在数据库里面的时间和版本
def get_tools_update_list(data):
    tools_update_list = []
    for dist in data:
        print("dist 变量 ->{}".format(dist))
        query_result = tools_query_sqlite3(dist['tools_name'])
        if len(query_result) > 0:
            today_tools_pushed_at = query_result[0]['pushed_at']
            # print("[!!] 今日获取时间: ", dist['pushed_at'], "获取数据库时间: ", today_tools_pushed_at, dist['tools_name'])
            if dist['pushed_at'] != today_tools_pushed_at:
                print("今日获取时间: ",dist['pushed_at'],"获取数据库时间: ",today_tools_pushed_at,dist['tools_name'],"update!!!!")
                #返回数据库里面的时间和版本
                tools_update_list.append({"api_url":dist['api_url'],"pushed_at":today_tools_pushed_at,"tag_name":query_result[0]['tag_name']})
            else:
                print("今日获取时间: ",dist['pushed_at'],"获取数据库时间: ",today_tools_pushed_at,dist['tools_name'],"   no update")
    return tools_update_list


# 监控用户是否新增仓库，不是 fork 的
def getUserRepos(user):
    try:
        api = "https://api.github.com/users/{}/repos".format(user)
        json_str = requests.get(api, headers=github_headers, timeout=10).json()
        today_date = datetime.date.today()

        for i in range(0, len(json_str)):
            created_at = re.findall('\d{4}-\d{2}-\d{2}', json_str[i]['created_at'])[0]
            if json_str[i]['fork'] == False and created_at == str(today_date):
                Verify = user_insert_into_sqlite3(json_str[i]['full_name'])
                print(json_str[i]['full_name'], Verify)
                if Verify == 0:
                    name = json_str[i]['name']
                    try:
                        description = json_str[i]['description']
                    except Exception as e:
                        description = "作者未写描述"
                    download_url = json_str[i]['html_url']
                    text = r'大佬' + r'** ' + user + r' ** ' + r'又分享了一款工具! '
                    body = "工具名称: " + name + " \r\n" + "工具地址: " + download_url + " \r\n" + "工具描述: " + "" + description
                    if load_config()[0] == "dingding":
                        dingding(text, body,load_config()[2],load_config()[3])
                    if load_config()[0] == "server":
                        server(text, body,load_config()[2])
                    if load_config()[0] == "pushplus":
                        pushplus(text, body,load_config()[2])
                    if load_config()[0] == "tgbot":
                        tgbot(text,body,load_config()[2],load_config()[3])
    except Exception as e:
        print(e, "github链接不通")

#获取用户或者组织信息插入到数据库
def user_insert_into_sqlite3(repo_name):
    conn = sqlite3.connect('data.db')
    cur = conn.cursor()
    sql_grammar = "SELECT repo_name FROM user_monitor WHERE repo_name = '{}';".format(repo_name)
    Verify = len(list(cur.execute(sql_grammar)))
    if Verify == 0:
        print("[+] 用户仓库表数据库里不存在{}".format(repo_name))
        cur.execute("INSERT INTO user_monitor (repo_name) VALUES ('{}')".format(repo_name))
        print("user_insert_into_sqlite3 函数: {}插入数据成功！".format(repo_name))
    else:
        print("[-] 用户仓库表数据库里存在{}".format(repo_name))
    conn.commit()
    conn.close()
    return Verify

#获取更新信息并发送到对应社交软件
def send_body(url,query_pushed_at,query_tag_name):
    # 考虑到有的工具没有 releases, 则通过 commits 记录获取更新描述
    # 判断是否有 releases 记录
    json_str = requests.get(url + '/releases', headers=github_headers, timeout=10).json()
    new_pushed_at = re.findall('\d{4}-\d{2}-\d{2}', requests.get(url, headers=github_headers, timeout=10).json()['pushed_at'])[0]
    if len(json_str) != 0:
        tag_name = json_str[0]['tag_name']
        if query_pushed_at < new_pushed_at :
            print("[*] 数据库里的pushed_at -->", query_pushed_at, ";;;; api的pushed_at -->", new_pushed_at)
            if tag_name != query_tag_name:
                try:
                    update_log = json_str[0]['body']
                except Exception as e:
                    update_log = "作者未写更新内容"
                download_url = json_str[0]['html_url']
                tools_name = url.split('/')[-1]
                text = r'** ' + tools_name + r' ** 工具,版本更新啦!'
                body = "工具名称：" + tools_name + "\r\n" + "工具地址：" + download_url + "\r\n" + "工具更新日志：" + "\r\n" + update_log
                if load_config()[0] == "dingding":
                    dingding(text, body,load_config()[2],load_config()[3])
                if load_config()[0] == "server":
                    server(text, body,load_config()[2])
                if load_config()[0] == "pushplus":
                    pushplus(text, body,load_config()[2])                    
                if load_config()[0] == "tgbot":
                    tgbot(text,body,load_config()[2],load_config()[3])
                conn = sqlite3.connect('data.db')
                cur = conn.cursor()
                sql_grammar = "UPDATE redteam_tools_monitor SET tag_name = '{}' WHERE tools_name='{}'".format(tag_name,tools_name)
                sql_grammar1 = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'".format(new_pushed_at, tools_name)
                cur.execute(sql_grammar)
                cur.execute(sql_grammar1)
                conn.commit()
                conn.close()
                print("[+] tools_name -->", tools_name, "pushed_at 已更新，现在pushed_at 为 -->", new_pushed_at,"tag_name 已更新，现在tag_name为 -->",tag_name)
            elif tag_name == query_tag_name:
                commits_url = url + "/commits"
                commits_url_response_json = requests.get(commits_url).text
                commits_json = json.loads(commits_url_response_json)
                tools_name = url.split('/')[-1]
                download_url = commits_json[0]['html_url']
                try:
                    update_log = commits_json[0]['commit']['message']
                except Exception as e:
                    update_log = "作者未写更新内容，具体点击更新详情地址的URL进行查看"
                text = r'** ' + tools_name + r' ** 工具小更新了一波!'
                body = "工具名称：" + tools_name + "\r\n" + "更新详情地址：" + download_url + "\r\n" + "commit更新日志：" + "\r\n" + update_log
                if load_config()[0] == "dingding":
                    dingding(text, body,load_config()[2],load_config()[3])
                if load_config()[0] == "feishu":
                    feishu(text,body,load_config()[2])
                if load_config()[0] == "server":
                    server(text, body,load_config()[2])
                if load_config()[0] == "pushplus":
                    pushplus(text, body,load_config()[2])                       
                if load_config()[0] == "tgbot":
                    tgbot(text,body,load_config()[2],load_config()[3])
                conn = sqlite3.connect('data.db')
                cur = conn.cursor()
                sql_grammar = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'".format(new_pushed_at,tools_name)
                cur.execute(sql_grammar)
                conn.commit()
                conn.close()
                print("[+] tools_name -->",tools_name,"pushed_at 已更新，现在pushed_at 为 -->",new_pushed_at)

        # return update_log, download_url, tools_version
    else:
        if query_pushed_at != new_pushed_at:
            print("[*] 数据库里的pushed_at -->", query_pushed_at, ";;;; api的pushed_at -->", new_pushed_at)
            json_str = requests.get(url + '/commits', headers=github_headers, timeout=10).json()
            update_log = json_str[0]['commit']['message']
            download_url = json_str[0]['html_url']
            tools_name = url.split('/')[-1]
            text = r'** ' + tools_name + r' ** 工具更新啦!'
            body = "工具名称：" + tools_name + "\r\n" + "工具地址：" + download_url + "\r\n" + "commit更新日志：" + "\r\n" + update_log
            if load_config()[0] == "dingding":
                dingding(text, body, load_config()[2], load_config()[3])
            if load_config()[0] == "feishu":
                feishu(text,body,load_config[2])
            if load_config()[0] == "server":
                server(text, body, load_config()[2])
            if load_config()[0] == "pushplus":
                pushplus(text, body,load_config()[2])                   
            if load_config()[0] == "tgbot":
                tgbot(text, body, load_config()[2], load_config()[3])
            conn = sqlite3.connect('data.db')
            cur = conn.cursor()
            sql_grammar = "UPDATE redteam_tools_monitor SET pushed_at = '{}' WHERE tools_name='{}'".format(new_pushed_at,tools_name)
            cur.execute(sql_grammar)
            conn.commit()
            conn.close()
            print("[+] tools_name -->", tools_name, "pushed_at 已更新，现在pushed_at 为 -->", new_pushed_at)
            # return update_log, download_url
# 创建md5对象
def nmd5(str):
    m = hashlib.md5()
    b = str.encode(encoding='utf-8')
    m.update(b)
    str_md5 = m.hexdigest()
    return str_md5
# 有道翻译
def translate(word):
    headerstr = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
    bv = nmd5(headerstr)
    lts = str(round(time.time() * 1000))
    salt = lts + '90'
    # 如果翻译失败，{'errorCode': 50}  请查看 fanyi.min.js: https://shared.ydstatic.com/fanyi/newweb/v1.1.7/scripts/newweb/fanyi.min.js
    # 搜索 fanyideskweb   sign: n.md5("fanyideskweb" + e + i + "Y2FYu%TNSbMCxc3t2u^XT")  ，Y2FYu%TNSbMCxc3t2u^XT是否改变，替换即可
    strexample = 'fanyideskweb' + word + salt + 'Y2FYu%TNSbMCxc3t2u^XT'
    sign = nmd5(strexample)
    data = {
        'i': word,
        'from': 'AUTO',
        'to': 'AUTO',
        'smartresult': 'dict',
        'client': 'fanyideskweb',
        'salt': salt,
        'sign': sign,
        'lts': lts,
        'bv': bv,
        'doctype': 'json',
        'version': '2.1',
        'keyfrom': 'fanyi.web',
        'action': 'FY_BY_CLICKBUTTION',
    }
    url = 'http://fanyi.youdao.com/translate_o?smartresult=dict&smartresult=rule'
    header = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'Referer': 'http://fanyi.youdao.com/',
        'Origin': 'http://fanyi.youdao.com',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'keep-alive',
        'Host': 'fanyi.youdao.com',
        'cookie': '_ntes_nnid=937f1c788f1e087cf91d616319dc536a,1564395185984; OUTFOX_SEARCH_USER_ID_NCOO=; OUTFOX_SEARCH_USER_ID=-10218418@11.136.67.24; JSESSIONID=; ___rl__test__cookies=1'
    }
    res = requests.post(url=url, data=data, headers=header)
    result_dict = res.json()
    result = ""
    for json_str in result_dict['translateResult'][0]:
        tgt = json_str['tgt']
        result += tgt
    return result

# 钉钉
def dingding(text, msg,webhook,secretKey):
    ding = cb.DingtalkChatbot(webhook, secret=secretKey)
    ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
## 飞书
def feishu(text,msg,webhook):
    ding = cb.DingtalkChatbot(webhook)
    ding.send_text(msg='{}\r\n{}'.format(text, msg), is_at_all=False)
# server酱  http://sc.ftqq.com/?c=code
def server(text, msg,sckey):
    try:
        uri = 'https://sc.ftqq.com/{}.send?text={}&desp={}'.format(sckey,text, msg)# 将 xxxx 换成自己的server SCKEY
        requests.get(uri, timeout=10)
    except Exception as e:
        pass
# pushplus  https://www.pushplus.plus/push1.html
def pushplus(text, msg,token):
    try:
        uri = 'https://www.pushplus.plus/send?token={}&title={}&content={}'.format(token,text, msg)# 将 xxxx 换成自己的pushplus的 token
        requests.get(uri, timeout=10)
    except Exception as e:
        pass        
# 添加Telegram Bot推送支持
def tgbot(text, msg,token,group_id):
    import telegram
    try:
        bot = telegram.Bot(token='{}'.format(token))# Your Telegram Bot Token
        bot.send_message(chat_id=group_id, text='{}\r\n{}'.format(text, msg))
    except Exception as e:
        pass

#判断是否存在该CVE
def exist_cve(cve):
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = requests.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        return 1
    except Exception as e:
        return 0

# 根据cve 名字，获取描述，并翻译
def get_cve_des_zh(cve):
    time.sleep(3)
    try:
        query_cve_url = "https://cve.mitre.org/cgi-bin/cvename.cgi?name=" + cve
        response = requests.get(query_cve_url, timeout=10)
        html = etree.HTML(response.text)
        des = html.xpath('//*[@id="GeneratedTable"]/table//tr[4]/td/text()')[0].strip()
        cve_time = html.xpath('//*[@id="GeneratedTable"]/table//tr[11]/td[1]/b/text()')[0].strip()
        if load_config()[-1]:
            return translate(des)
        return des, cve_time
    except Exception as e:
        pass
#发送CVE信息到社交工具
def sendNews(data):
    try:
        text = '有新的CVE送达! \r\n** 请自行分辨是否为红队钓鱼!!! **'
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                cve_name = re.findall('(CVE\-\d+\-\d+)', data[i]['cve_name'])[0].upper()
                cve_zh, cve_time = get_cve_des_zh(cve_name)
                body = "CVE编号: " + cve_name + "  --- " + cve_time + " \r\n" + "Github地址: " + str(data[i]['cve_url']) + "\r\n" + "CVE描述: " + "\r\n" + cve_zh
                if load_config()[0] == "dingding":
                    dingding(text, body, load_config()[2], load_config()[3])
                    print("钉钉 发送 CVE 成功")
                if load_config()[0] == "feishu":
                    feishu(text, body, load_config()[2])
                    print("飞书 发送 CVE 成功")
                if load_config()[0] == "server":
                    server(text, body, load_config()[2])
                    print("server酱 发送 CVE 成功")
                if load_config()[0] == "pushplus":
                    pushplus(text, body, load_config()[2])
                    print("pushplus 发送 CVE 成功")                    
                if load_config()[0] == "tgbot":
                    tgbot(text, body, load_config()[2], load_config()[3])
                    print("tgbot 发送 CVE 成功")
            except IndexError:
                pass
    except Exception as e:
        print("sendNews 函数 error:{}".format(e))

#发送信息到社交工具
def sendKeywordNews(keyword, data):
    try:
        text = '有新的关键字监控 - {} - 送达! \r\n** 请自行分辨是否为红队钓鱼!!! **'.format(keyword)
        # 获取 cve 名字 ，根据cve 名字，获取描述，并翻译
        for i in range(len(data)):
            try:
                keyword_name =  data[i]['keyword_name']
                body = "项目名称: " + keyword_name + "\r\n" + "Github地址: " + str(data[i]['keyword_url']) + "\r\n"
                if load_config()[0] == "dingding":
                    dingding(text, body, load_config()[2], load_config()[3])
                    print("钉钉 发送 CVE 成功")
                if load_config()[0] == "feishu":
                    feishu(text, body, load_config()[2])
                    print("飞书 发送 CVE 成功")
                if load_config()[0] == "server":
                    server(text, body, load_config()[2])
                    print("server酱 发送 CVE 成功")
                if load_config()[0] == "pushplus":
                    pushplus(text, body, load_config()[2])
                    print("pushplus 发送 CVE 成功")                    
                if load_config()[0] == "tgbot":
                    tgbot(text, body, load_config()[2], load_config()[3])
                    print("tgbot 发送 CVE 成功")
            except IndexError:
                pass
    except Exception as e:
        print("sendKeywordNews 函数 error:{}".format(e))

#main函数
if __name__ == '__main__':
    print("cve 、github 工具 和 大佬仓库 监控中 ...")
    #初始化部分
    create_database()

    while True:
        tools_list, keyword_list, user_list = load_tools_list()
        tools_data = get_pushed_at_time(tools_list)
        tools_insert_into_sqlite3(tools_data)   # 获取文件中的工具列表，并从 github 获取相关信息，存储下来

        print("\r\n\t\t  用户仓库监控 \t\t\r\n")
        for user in user_list:
            getUserRepos(user)
        #CVE部分
        print("\r\n\t\t  CVE 监控 \t\t\r\n")
        cve_data = getNews()
        if len(cve_data) > 0 :
            today_cve_data = get_today_cve_info(cve_data)
            sendNews(today_cve_data)
            cve_insert_into_sqlite3(today_cve_data)

        print("\r\n\t\t  关键字监控 \t\t\r\n")
        # 关键字监控 , 最好不要太多关键字，防止 github 次要速率限制  https://docs.github.com/en/rest/overview/resources-in-the-rest-api#secondary-rate-limits=
        for keyword in keyword_list:
             time.sleep(1)  # 每个关键字停 1s ，防止关键字过多导致速率限制
             keyword_data = getKeywordNews(keyword)

             if len(keyword_data) > 0:
                today_keyword_data = get_today_keyword_info(keyword_data)
                if len(today_keyword_data) > 0:
                    sendKeywordNews(keyword, today_keyword_data)
                    keyword_insert_into_sqlite3(today_keyword_data)

        print("\r\n\t\t  红队工具监控 \t\t\r\n")
        time.sleep(5*60)
        tools_list_new, keyword_list, user_list = load_tools_list()
        data2 = get_pushed_at_time(tools_list_new)      # 再次从文件中获取工具列表，并从 github 获取相关信息,
        data3 = get_tools_update_list(data2)        # 与 3 分钟前数据进行对比，如果在三分钟内有新增工具清单或者工具有更新则通知一下用户
        for i in range(len(data3)):
            try:
                send_body(data3[i]['api_url'],data3[i]['pushed_at'],data3[i]['tag_name'])
            except Exception as e:
                print("main函数 try循环 遇到错误-->{}".format(e))
