import requests
import time
import datetime
import glob
import os

now = datetime.datetime.now()
tasks = glob.glob("绿盟\*.txt")
today= now.strftime('%Y'+"年"+'%m'+"月"+'%d'+"日") 

def set_time_day():
    now = datetime.datetime.now()
    the_time_1 = now.strftime('%Y'+"-"+'%m') 
    the_time_2 = now.strftime('%d')
    the_time_2 = str(int(the_time_2) + 1)
    the_time = the_time_1+"-"+the_time_2
    return the_time

def set_ip(path): 
    ip_info = ""
    with open(path,"r+") as f1:
        ip_list = f1.readlines()
        for ip in ip_list:
            ip_info = ip_info + str(ip)     
    return ip_info

def login():
    burp0_url = "*****************************/accounts/login_view/"
    burp0_cookies = {"sessionid": "4f375fl6clie8sh9xd8fv61egxflk9e1", "csrftoken": "YX13FKZdvKGt2oTne9OydUC1tXDbvYFB9NoklpwPtENEZI7AEBDBvmAqkCjwU7K2"}
    burp0_headers = {"Connection": "close", "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "https://132.121.80.100", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Referer": "https://132.121.80.100/accounts/login/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
    burp0_data = {"username": "***************", "password": "*****************", "csrfmiddlewaretoken": "efmNF8i7el4DzhBGKXc0HPUCSaorToezp5J4lNPJcfbOwBPTap13ZhS1JP4Mixj0"}
    rq = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
    cookies = rq.cookies
    cookie = requests.utils.dict_from_cookiejar(cookies)
    cookie = cookie["sessionid"]
    return cookie

def set_task_lvmeng(tasks):
    scan_log = "绿盟扫描记录.txt"
    for hour,task in enumerate(tasks):
        try:
            hours = hour - 6*(hour // 6)
            path = os.path.abspath(task)
            name = str(task).replace(".txt","")
            name = name.replace("绿盟\\","")
            burp0_url = "*****************************/task/vul/tasksubmit"
            burp0_cookies = {"csrftoken": "efmNF8i7el4DzhBGKXc0HPUCSaorToezp5J4lNPJcfbOwBPTap13ZhS1JP4Mixj0", "sessionid": "878bxz1t5s6z8zljuymblxjy6t1osm2l", "left_menustatue_NSFOCUSRSAS": "0|0|https://132.121.80.100/task/task_entry/"}
            burp0_headers = {"Connection": "close", "Accept": "*/*", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded", "Origin": "https://132.121.80.100", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://132.121.80.100/task/index/1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
            burp0_data = {"csrfmiddlewaretoken": "efmNF8i7el4DzhBGKXc0HPUCSaorToezp5J4lNPJcfbOwBPTap13ZhS1JP4Mixj0", "vul_or_pwd": "vul", "config_task": "taskname", "task_config": '', "diff": "write something", "target": "ip", "ipList": "132.10.10.10", "domainList": '', "name": "test", "exec": "timing", "exec_timing_date": "2021-01-23 01:00:00", "exec_everyday_time": "00:00", "exec_everyweek_day": "1", "exec_everyweek_time": "00:00", "exec_emonthdate_day": "1", "exec_emonthdate_time": "00:00", "exec_emonthweek_pre": "1", "exec_emonthweek_day": "1", "exec_emonthweek_time": "00:00", "tpl": "0", "login_check_type": "login_check_type_vul", "batch_ssh_ip": '', "batch_ssh_protocol": "SSH", "batch_ssh_port": '', "batch_ssh_name": '', "exec_range": '', "scan_pri": "2", "taskdesc": '', "report_type_html": "html", "report_content_sum": "sum", "report_content_host": "host", "report_tpl_sum": "1", "report_tpl_host": "101", "report_ifsent_type": "html", "report_ifsent_email": '', "port_strategy_userports": "1-100,443,445", "port_strategy": "allports", "port_speed": "3", "port_tcp": "T", "live_udp_ports": "25,53", "sping_delay": "1", "scan_level": "3", "timeout_plugins": "40", "timeout_read": "5", "alert_msg": "\xe8\xbf\x9c\xe7\xa8\x8b\xe5\xae\x89\xe5\x85\xa8\xe8\xaf\x84\xe4\xbc\xb0\xe7\xb3\xbb\xe7\xbb\x9f\xe5\xb0\x86\xe5\xaf\xb9\xe6\x82\xa8\xe7\x9a\x84\xe4\xb8\xbb\xe6\x9c\xba\xe8\xbf\x9b\xe8\xa1\x8c\xe5\xae\x89\xe5\x85\xa8\xe8\xaf\x84\xe4\xbc\xb0\xe3\x80\x82", "encoding": "GBK", "bvs_task": "no", "pwd_smb": "yes", "pwd_type_smb": "c", "pwd_user_smb": "smb_user.default", "pwd_pass_smb": "smb_pass.default", "pwd_telnet": "yes", "pwd_type_telnet": "c", "pwd_user_telnet": "telnet_user.default", "pwd_pass_telnet": "telnet_pass.default", "pwd_ssh": "yes", "pwd_type_ssh": "c", "pwd_user_ssh": "ssh_user.default", "pwd_pass_ssh": "ssh_pass.default", "pwd_timeout": "5", "pwd_timeout_time": "120", "pwd_interval": "0", "pwd_num": "0", "pwd_threadnum": "5", "loginarray": "[{\"ip_range\": \"132.10.10.10\", \"admin_id\": \"\", \"protocol\": \"\", \"port\": \"\", \"os\": \"\", \"ssh_auth\": \"\", \"user_name\": \"\", \"user_pwd\": \"\", \"user_ssh_key\": \"\", \"ostpls\": [], \"apptpls\": [], \"dbtpls\": [], \"virttpls\": [], \"bdstpls\": [], \"devtpls\": [], \"statustpls\": \"\", \"tpl_industry\": \"\", \"tpllist\": [], \"tpllistlen\": 0, \"web_login_url\": \"\", \"web_login_cookie\": \"\", \"jhosts\": [], \"tpltype\": \"\", \"protect\": \"\", \"protect_level\": \"\", \"jump_ifuse\": \"\", \"host_ifsave\": \"\", \"oracle_ifuse\": \"\", \"ora_username\": \"\", \"ora_userpwd\": \"\", \"ora_port\": \"\", \"ora_usersid\": \"\", \"weblogic_ifuse\": \"\", \"weblogic_system\": \"\", \"weblogic_version\": \"\", \"weblogic_user\": \"\", \"weblogic_path\": \"\", \"web_login_wblgc_ifuse\": \"\", \"web_login_wblgc_user\": \"\", \"web_login_wblgc_pwd\": \"\", \"web_login_wblgc_path\": \"\"}]"}
            burp0_cookies["sessionid"] = login()
            burp0_data["ipList"] = set_ip(path)
            burp0_data["exec_timing_date"] = set_time_day() +" 0" + str(hours) + ":00:00"
            burp0_data["name"] = today + "任务:" + str(hour) + " " + name 
            rq = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
            if "suc" in rq.text:
                info = str(today)+":"+name+"任务设定成功,定时扫描时间:"+str(burp0_data["exec_timing_date"])+"\n"
                print(info)
                with open(scan_log,"a+",encoding="utf-8") as f:
                    f.write(info)
            else:
                info = str(today)+":"+name+"任务设定失败"+"\n"
                print(info)
                with open(scan_log,"a+",encoding="utf-8") as f1:
                    f1.write(info)
        finally:
            continue
    return 

if __name__ == '__main__':

    set_task_lvmeng(tasks)