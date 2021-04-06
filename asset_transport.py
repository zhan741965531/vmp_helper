import requests
import json

burp0_cookies = {"lang": "\"\"", "JSESSIONID": "5229495A9509F3C3569D22F615AD87C7"}
with open("cookie.txt","r") as f:
    burp0_cookies["JSESSIONID"] = f.read()
url = "********************"

#获取现有系统的固定id
def get_info_list():
    burp0_url = "********************/smp/asset/group/list?groupId=0&viewType=manage"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "********************/smp/asset/viewTopoMain1?groupId=10885&viewType=manage&view=list&switchView=&selectedNode=", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    rq = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify=False)
    rq = json.loads(rq.text)
    return rq

#执行资产迁移动作
def aciton(target_id,current_id,proxy_id):
    if target_id == current_id:
        print(current_id,"已在下线资产目录中，无需转移。")
        pass
    else:
        burp0_url = "********************/smp/asset/moveListAjax?targetGroupId="+str(target_id)+"&currentGroupId="+str(current_id)+"&proxyIds="+str(proxy_id)+"&viewType=manage"
        burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "********************/smp/asset/viewTopoMain1?groupId=10885&viewType=manage&view=list&switchView=&selectedNode=", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
        rq = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify=False)
        rq = rq.text
        print(current_id,"转移中成功！")
    return 

#搜索此ip所有的资产类型
def research(ip):
    burp0_url = "********************/smp/asset/assetBysx/viewAssetList?groupId=0&viewType=classify&operate=search&ipRangeStart="+ str(ip) +"&typeids="
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded", "Origin": "********************", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "********************/smp/asset/viewAssetList?groupId=0&viewType=classify&selectedNode=&switchView=false", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    burp0_data = {"_search": "false", "nd": "1612751578195", "rows": "20", "page": "1", "sidx": "ip", "sord": "asc"}
    rq = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
    rq = json.loads(rq.text)
    return rq

#如果测试节点下线资产不存在则创建下线系统，形如：xx系统-下线资产
def creat_system(target_name):
    print("创建下线系统:",target_name)
    burp0_url = "********************/smp/asset/group/insert"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "X-Requested-With": "XMLHttpRequest", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Content-Type": "application/x-www-form-urlencoded", "Origin": "********************", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "********************/smp/asset/management/main?portal_id=portal-asset&wicket_id=module-asset_wickets-asset-management&root_id=-1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    burp0_data = {"parentId": "10398", "value": '', "name":target_name, "description": '', "viewType": "manage", "managerId": '', "type": "0"}
    requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data,verify=False)
    return

#获取所有的系统id信息
def get_system_id():
    burp0_url = "********************/smp/asset/group/read?groupId=11125&viewType=manage"
    burp0_headers = {"Connection": "close", "Accept": "application/json, text/javascript, */*; q=0.01", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "X-Requested-With": "XMLHttpRequest", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "********************/smp/asset/management/main?portal_id=portal-asset&wicket_id=module-asset_wickets-asset-management&root_id=-1", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify=False)
    return
#获取该资产所在的系统名，当前的id和资产id
def get_pro_ids_and_manageGroupId(ip):
    transport_list = []
    list_info = research(ip)
    system_name = ""
    proxy_id = ""
    current_id = ""
    for data in list_info["data"]:
        IP_list = []
        if str(data["ip"]) == str(ip):
            if data["manageGroup"] is None:
                print(ip,"该资产为孤儿资产,将该资产的系统名设为：孤儿")
                system_name = "孤儿"
                proxy_id = data["id"]
                current_id = data["manageGroupId"]
                IP_list.append(system_name)
                IP_list.append(current_id)
                IP_list.append(proxy_id)
                transport_list.append(IP_list)
            else:
                system_name = str(data["manageGroup"]["name"])
                proxy_id = data["id"]
                current_id = data["manageGroupId"]
                IP_list.append(system_name)
                IP_list.append(current_id)
                IP_list.append(proxy_id)
                transport_list.append(IP_list)
            print("系统为:",system_name,"当前id:",current_id,"资产id",proxy_id,"资产名称:",data["name"])
        else:
            print("该资产为:",data["ip"],"不是:",ip)
    return transport_list

#获取目标系统的id
def get_Target_id(target_name):
    target_id = "不存在"
    list_info = get_info_list()
    for data in list_info["children"]:
        for data1 in data["children"]:
            for data2 in data1["children"]:
                    if data2["node"]["name"] == str(target_name):
                        target_id = data2["node"]["id"]
                    else:
                        pass
    print("获取到",target_name,"的id为:",target_id)
    return target_id

#启动程序
def asset_down_start():
    with open("ip.txt","r") as f:
        ips = []
        for ip in f.readlines():
            ip = ip.replace("\n","")
            ips.append(ip)
    print(ips)
    for ip in ips:
        datas = get_pro_ids_and_manageGroupId(ip)
        print(datas)
        for data in datas:
            if "下线资产" in str(data[0]):
                system_name = data[0]
            else:
                system_name = data[0] + "下线资产"
            current_id = data[1]
            proxy_id = data[2]
            if get_Target_id(system_name) == "不存在":
                creat_system(system_name)
                target_id = get_Target_id(system_name)
            else:
                target_id = get_Target_id(system_name)
            print("获取资产ip:",ip.replace("\r\n","")," 目标系统的id:",target_id," 当前id为:",current_id," 资产唯一标识:",proxy_id)
            aciton(target_id,current_id,proxy_id)

if __name__ == '__main__':
    asset_down_start()
