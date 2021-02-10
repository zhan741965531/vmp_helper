import requests
import json
import xlrd
import datetime
import time
import random
import urllib3
import os
import xlwt
import set_Task_lvmeng
import set_Task_tianjing
import asset_transport
from exchangelib import Credentials, Account, DELEGATE, \
    Configuration, NTLM, Message, Mailbox, HTMLBody,FileAttachment,HTMLBody
from exchangelib.protocol import BaseProtocol, NoVerifyHTTPAdapter
from email.mime.text import MIMEText
from email.utils import formataddr

burp0_cookies = {"lang": "\"\"", "JSESSIONID": "9BE3174CB1FB5841563AFC403CA6CF34"}
now = datetime.datetime.now()
today = now.strftime('%Y'+"年"+'%m'+"月"+'%d'+"日") 
urllib3.disable_warnings() 
BaseProtocol.HTTP_ADAPTER_CLS = NoVerifyHTTPAdapter
cred = Credentials('************', '**********')
url = "https://10.118.2.151:8443"

config = Configuration(
    server = '*********', 
    credentials = cred, 
    auth_type = NTLM
)

account = Account(
    primary_smtp_address='***********', 
    config=config, 
    autodiscover=False, 
    access_type=DELEGATE
)

def downall_and_send():
    list_name_id = get_sysinfo()
    for value in list_name_id:
        try:    
            down_logs = str(today) + "下载漏洞信息记录.txt"
            id = list_name_id[value]
            print(value,list_name_id[value])
            burp0_url = url + "/smp/holeHostDataset/export"
            burp0_headers = {"Connection": "close", "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "iframe", "Referer": "/smp/holeHostDataset/listByStatus?history=2", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
            burp0_data = {"vulnName": '', "assetIp": '', "vulnValue": '', "sysplatId": "11038", "history": "2", "exportflg": "1", "assetIp2": '', "vulnName2": '', "vulnValue2": '', "sysplatId2": "11038", "___validator_form_idx___": "0"}
            burp0_data["sysplatId"] = id
            burp0_data["sysplatId2"] = id
            address = str(get_user_mail(id))
            name = str(value) + ".xls"
            rq = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
            with open(name,"wb") as f:
                f.write(rq.content)
            with open(down_logs,"a+",encoding="utf-8") as f1:
                f1.write(name)
                f1.write("\n")
            mail_send(name,address)
        finally:
            continue
    return 

def get_sysinfo():
    relation_id_name = {}
    burp0_url = url + "/smp/asset/group/getGroupTree?viewType=manage"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "/smp/asset/management/main?portal_id=portal-asset&wicket_id=module-asset_wickets-asset-management&root_id=-1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    rq = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify= False)
    data = json.loads(rq.text)
    for child in data["children"]:
        for child2 in child["children"]:
            for child3 in child2["children"]:
                name = child3["node"]["name"]
                name= name.replace("\r\n","")
                id = child3["node"]["id"]
                relation_id_name[name] = id
                #print(child3["node"]["id"],":",child3["node"]["name"])
    return relation_id_name

def get_user_mail(id):
    burp0_url = url + "/smp/asset/group/read?groupId=" + str(id) + "&viewType=manage"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "/smp/asset/management/main?portal_id=portal-asset&wicket_id=module-asset_wickets-asset-management&root_id=-1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    rq = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify=False)
    data = rq.text
    data = json.loads(data)
    print(data["manageEmail"])
    mail = [data["manageEmail"]]
    return mail

def mail_send(name_user,mail_address):
    data = mail_body(name_user)
    mail_Data = data[0]
    is_send = int(data[1])
    if is_send == 0:
        file = name_user.replace(".xls","")
        now = datetime.datetime.now()
        the_time = now.strftime('%Y'+"年"+'%m'+"月"+'%d'+"日")
        m = Message(
                account=account,
                subject= the_time + file + "漏洞清单" + "模拟发送给:" + str(mail_address),
                body= HTMLBody(mail_Data),
                to_recipients = [Mailbox(email_address='*******@qq.com')],
                cc_recipients = ["************@qq.com"]
            )
        with open(name_user,"rb") as f:
            conf = f.read()
        attch = FileAttachment(name=name_user,content=conf)
        m.attach(attch)
        m.send_and_save()
    else:
        pass
    return 

def mail_body(file_path):
    the_h = 0
    the_m = 0
    no_send = 0
    info_list =[]
    mail_send_log = str(today) + "mail_send_log.txt"
    workbook = xlrd.open_workbook(file_path)
    sheet = workbook.sheet_by_name("主机漏洞扫描任务漏洞信息")
    nrows = sheet.nrows
    list_info = sheet.col_values(8)
    for string in list_info:
        if  string == "高危险":
            the_h = the_h + 1
        elif string == "中危险":
            the_m = the_m + 1
        else:
            pass
    if the_h ==0 | the_m ==0:
        no_send = 1
    else:
        with open(mail_send_log,"a",encoding="utf-8") as f1:
            f1.write(str(today))
            f1.write(":")
            info ="现存高危漏洞%d个,中危险漏洞%d个,总计%d个" % (the_h,the_m,the_h+the_m)
            file_path = str(file_path)
            file_path = file_path.replace(".xls","")
            f1.write(file_path+info)
            f1.write("\n")
    body =f"""
<br> 您好：
<br> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;附件为漏洞扫描结果，具体漏洞已导入漏洞平台/smp/login.jsp，现存高危漏洞{the_h}个，中危漏洞{the_m}个。请系统负责人尽快安排人员进行整改，整改完成后请发邮件给我方进行复查。
<br> 
<br> **** ***********
<br> ****************
    """
    return body,no_send

def get_user():
    user_info_name = str(today) + "User_info.txt"
    burp0_url = url + "/smp/asset/group/getUsers"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Origin": "", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "/smp/asset/management/main?portal_id=portal-asset&wicket_id=module-asset_wickets-asset-management&root_id=-1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    rq = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify=False)
    rq = json.loads(rq.text)
    for each_data in rq:
        user_id = str(each_data["userId"])
        name = each_data["name"]
        realname = each_data["realname"]
        password = each_data["password"]
        email = str(each_data["email"])
        mobile = str(each_data["mobile"])
        user_info = "用户id:"+user_id+"  用户名:"+name+"  真实姓名:"+realname+"  密码hash:"+password+"  电子邮件:"+email+"  手机号码:"+mobile
        with open(user_info_name,"a",encoding="utf-8") as f:
            f.write(user_info)
            f.write("\n")
        print(user_info)
    return

def get_asset(system_name,system_id):
    asset_list = []
    name  = str(system_name)
    name = name.replace("/","")
    burp0_url = url + "/smp/asset/assetBysx/viewAssetList?groupId="+ str(system_id) +"&viewType=manage&selectedNode=&switchView=&ip=&name=&id=0"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded", "Origin": "", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "/smp/asset/viewAssetList?groupId=11069&viewType=manage&selectedNode=&switchView=", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    burp0_data = {"_search": "false", "nd": "1611897848734", "rows": "500", "page": "1", "sidx": "ip", "sord": "asc"}
    rq = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
    rq = json.loads(rq.text)
    for asset in rq["data"]:
        ip = asset["ip"]
        asset_list.append(ip)
    asset_list = list(set(asset_list))
    fenlei(name,asset_list)
    print(list(set(asset_list)))
    system_asset_number = len(asset_list)
    return system_asset_number

def fenlei(file_name,ip_list):
    ip_list = list(ip_list)
    name = str(file_name)
    name = name + ".txt"
    for ip in ip_list:
        if "10.123" in str(ip) or "192.168" in str(ip):
            with open("天镜/"+name,"a",encoding="utf-8") as f:
                f.write(ip)
                f.write("\n")
        else:
            with open("绿盟/"+name,"a",encoding="utf-8") as f2:
                f2.write(ip)
                f2.write("\n")
    return

def asset_generate():
    list_info = get_sysinfo()
    for x in list_info:
        system_name = x
        log_asset_name = str(today) + "(系统-id-资产数量).txt"
        system_id = str(list_info[x])
        number = str(get_asset(system_name,system_id))
        print(system_name,"现存资产数量:",number)
        with open(log_asset_name,"a",encoding="utf-8") as f1:
            f1.write(system_name)
            f1.write(":")
            f1.write(system_id)
            f1.write(":")
            f1.write(number)
            f1.write("\n")
    return 

def set_some_task():
    task_list_lvmeng = []
    task_list_tianjing = []
    with open("扫描任务.txt","r+",encoding="utf-8") as f:
        tasks = f.readlines()
        for task in tasks:
            task = str(task).replace("\n","")
            task_1 = "绿盟\\" + task + ".txt"
            task_2 = "天镜\\" + task + ".txt"
            task_list_lvmeng.append(task_1)
            task_list_tianjing.append(task_2)
        set_Task_lvmeng.set_task_lvmeng(task_list_lvmeng)
        set_Task_tianjing.set_task_tianjing(task_list_tianjing)
    return 

def start():
    banner = """
                 _       _ _     _          _
  _____  ___ __ | | ___ (_) |_  | |__   ___| |_ __   ___ _ __
 / _ \ \/ / '_ \| |/ _ \| | __| | '_ \ / _ \ | '_ \ / _ \ '__|
|  __/>  <| |_) | | (_) | | |_  | | | |  __/ | |_) |  __/ |
 \___/_/\_\ .__/|_|\___/|_|\__| |_| |_|\___|_| .__/ \___|_|
          |_|                                |_|
          
                                              Author: zhtty
                                              Version: v1
                                              Python Version: v3.9
        0 ==> 退出助手
        1 ==> 获取所有用户信息
        2 ==> 获取有所系统资产
        3 ==> 执行预设任务
        4 ==> 下载所有漏洞信息并发送给对应负责人
        5 ==> 一键下线资产至测试节点
          """
    print(banner)
    case = int(input())
    if case == 0:
        exit
    elif case == 1:
        get_user()
    elif case == 2:
        asset_generate()
    elif case == 3:
        set_some_task()
    elif case == 4:
        downall_and_send()
    elif case == 5:
        asset_transport.asset_down_start()
    else:
        print("                选择出错,重新选择")
        start()
    return 

if __name__ == '__main__':
    start()