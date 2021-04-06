import requests
import time
import datetime
import glob
import os

session = requests.session()
now = datetime.datetime.now()
tasks = glob.glob("天镜/*.txt")
today = now.strftime('%Y'+"年"+'%m'+"月"+'%d'+"日") 
burp0_url = "https://10.123.182.187:443/vulntask/addTask.action"
burp0_cookies = {"JSESSIONID": "81419CA013D37F73CC0D6A79C4A1C061"}
burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Origin": "https://10.123.182.187", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://10.123.182.187/vulntask/loadAdd.action?vulnTaskForm.execType=3&_requestType=popWindow", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"}
burp0_data = {"vulnTaskForm.taskName": "test", "vulnTaskForm.scanTarget": "", "vulnTaskForm.excludeTarget": '', "vulnTaskForm.taskLimitTime": '', "vulnTaskForm.policyID": "4028fe023121e14a013146c3dd915b7f", "vulnTaskForm.execType": "3", "planTime.date": "2021-01-21", "planTime.hour": "", "planTime.minute": "00", "periodType": "1", "eachDay.hour": "0", "eachDay.minute": "0", "eachWeek.dayOfWeek": "2", "eachWeek.hour": "0", "eachWeek.minute": "0", "eachMonth.dayOfMonth": "1", "eachMonth.hour": "0", "eachMonth.minute": "0", "endSchdTime.date": "2021-02-20", "endSchdTime.hour": "15", "endSchdTime.minute": "0", "vulnTaskForm.emailAddress": '', "vulnTaskForm.reportType": "1", "advanceParaForm.hostLiveCheckType": "1", "advanceParaForm.customHostLiveCheckPort": "22,23,25,80,139,445,3389,8080", "advanceParaForm.taskLevel": "1", "advanceParaForm.guessTime": "20", "advanceParaForm.guessInterval": "0", "advanceParaForm.pluginTimeout": "40", "advanceParaForm.scanAfterNetConn": "0", "advanceParaForm.timeInterval": "0", "advanceParaForm.enableByOSScan": "1", "advanceParaForm.windowsDomainName": '', "advanceParaForm.windowsDomainNetBios": '', "advanceParaForm.windowsDomainUsername": '', "advanceParaForm.windowsDomainUserPwd": '', "advanceParaForm.noticeContent": '', "advanceParaForm.sendDelay": "1", "advanceParaForm.receiveDelay": "2", "advanceParaForm.connectDelay": "2", "advanceParaForm.dependable": "1", "advanceParaForm.portScanningType": "5", "advanceParaForm.portScanEnable": "1", "advanceParaForm.portScanningStrategy": "1", "advanceParaForm.customPortScanEnable": "1", "advanceParaForm.customScanPort": "1-65535", "advanceParaForm.passwordGuessTypes": "1", "advanceParaForm.passwordGuessTypes": "9", "advanceParaForm.passwordGuessTypes": "6", "advanceParaForm.passwordGuessTypes": "8", "advanceParaForm.instance": '', "advanceParaForm.authParas": '', "advanceParaForm.oracle.port": "1521", "advanceParaForm.oracle.instanceName": "orcl", "advanceParaForm.oracle.dbType": "1", "advanceParaForm.oracle.userName": "sys", "advanceParaForm.oracle.password": "manager", "advanceParaForm.mssql.port": "1433", "advanceParaForm.mssql.dbType": "2", "advanceParaForm.mssql.userName": "sa", "advanceParaForm.mssql.password": "test1234", "advanceParaForm.mysql.port": "3306", "advanceParaForm.mysql.instanceName": "mysql", "advanceParaForm.mysql.dbType": "3", "advanceParaForm.mysql.userName": "root", "advanceParaForm.mysql.password": "test1234", "advanceParaForm.sybase.port": "5000", "advanceParaForm.sybase.instanceName": "master", "advanceParaForm.sybase.dbType": "4", "advanceParaForm.sybase.userName": "sa", "advanceParaForm.sybase.password": "test1234", "advanceParaForm.db2.port": "50000", "advanceParaForm.db2.instanceName": "DWCTRLDB", "advanceParaForm.db2.dbType": "5", "advanceParaForm.db2.userName": "db2admin", "advanceParaForm.db2.password": "test1234", "vulnTaskForm.remoteNodeIds": '', "vulnTaskForm.localScan": "false"}

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

def set_task_tianjing(tasks):
    scan_log = "天镜扫描记录.txt"
    for hour,task in enumerate(tasks):
        try:
            path = os.path.abspath(task)
            name = str(task).replace(".txt","")
            name = name.replace("天镜\\","")
            burp0_data["vulnTaskForm.taskName"] = today + "任务" + str(hour) + " " + name   
            burp0_data["vulnTaskForm.scanTarget"] = set_ip(path)
            burp0_data["planTime.date"] = set_time_day()
            burp0_data["planTime.hour"] = hour - 6*(hour // 6)
            rq = session.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
            if str({}) in rq.text:
                info = str(today)+":"+name+"任务设定成功,定时扫描时间:"+str(burp0_data["planTime.date"])+"\n"
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
    
    set_task_tianjing(["*********************"])