import os
import xlrd
import xlwt
import requests
import datetime

now = datetime.datetime.now()
today = now.strftime('%Y'+""+'%m'+""+'%d'+"") 

class read_data():
    def __init__(self,file_path,sheet_name=0):
        super().__init__()
        self.file_path = file_path
        self.sheet_name = sheet_name
        sheet_name = []
        return

    def get_list(self):
        tables  = xlrd.open_workbook(str(self.file_path))
        sheet_data = tables.sheet_by_name(str(self.sheet_name))
        table = sheet_data
        the_length = table.nrows
        list_the_h = table.col_values(11)
        list_the_m = table.col_values(17)
        list_bumeng = table.col_values(0)#部门
        list_keshi = table.col_values(1)#科室
        list_fuzeren = table.col_values(2)
        list_yewuxitong = table.col_values(3)
  #     print(list_bumeng,list_fuzeren)
        return list_bumeng,list_keshi,list_fuzeren,list_yewuxitong,list_the_h,list_the_m

    def get_info(self):
        data_file = self.file_path
        server_exploit = read_data(data_file,"主机应用层漏洞")
        sql_exploit = read_data(data_file,"主机数据库漏洞")
        system_exploit = read_data(data_file,"主机操作系统漏洞")
        info_server = server_exploit.get_list()
        info_sql = sql_exploit.get_list()
        info_system = system_exploit.get_list()
        all_info = []
        for each in range(len(info_server[4])):
            if type(info_server[4][each]) == float:
                h = info_server[4][each] + info_sql[4][each] + info_system[4][each]
                m = info_server[5][each] + info_sql[5][each] + info_system[5][each]
                all_info.append(int(h+m))
            else:
                all_info.append(info_server[4][each])
        return info_server,all_info

def get_xls():
    burp0_url = "******************************8/smp/businessWeeklyHoleCountController/exportBusinessWeeklyHoleCount?networkType=0"
    burp0_cookies = {"lang": "\"\"", "JSESSIONID": "00EE076AE95C9D04BFC12A5E3C1B6F8A"}
    with open("cookie.txt","r") as f:
        cookie = f.read()
    burp0_cookies["JSESSIONID"] = cookie
    burp0_headers = {"Connection": "close", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "iframe", "Referer": "******************************8/smp/businessWeeklyHoleCountController/viewBusinessWeeklyTable?type=web&networkType=0", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}
    rq = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies,verify=False)
    with open("省公司业务系统周报.xls","wb+") as f:
        f.write(rq.content)
    return os.path.abspath("省公司业务系统周报.xls")

def generate():
    data = read_data(get_xls())
    info = data.get_info()
    bumeng = info[0][0]
    keshi = info[0][1]
    fuzeren = info[0][2]
    yewuxitong = info[0][3]
    exploits = info[1]
    print(exploits,len(exploits))

    for index,bumen_data in enumerate(bumeng):
        if bumen_data =="数据中心" or bumen_data =="运营中心" or bumen_data =="计费中心":
            bumeng[index] = "数创中心"   
    #print(bumeng,keshi,fuzeren,yewuxitong,exploits)

    #格式设置
    sytle = xlwt.XFStyle()
    sytle1 = xlwt.XFStyle()
    sytle2 = xlwt.XFStyle()
    font = xlwt.Font()
    font.name = "宋体"
    font.bold = True
    font.colour_index = 8
    font.height = 240
    sytle.font = font
    alignment  = xlwt.Alignment()
    alignment.horz = 2
    sytle.alignment = alignment
    sytle1.alignment =alignment
    borders = xlwt.Borders()
    borders.left = xlwt.Borders.THIN
    borders.right = xlwt.Borders.THIN
    borders.top = xlwt.Borders.THIN
    borders.bottom = xlwt.Borders.THIN
    borders.left_colour = 0
    borders.right_colour = 0
    borders.top_colour = 0
    borders.bottom_colour = 0
    sytle.borders = borders
    sytle1.borders = borders
    sytle2.borders = borders
    pattern = xlwt.Pattern()
    pattern.pattern = xlwt.Pattern.SOLID_PATTERN
    pattern.pattern_fore_colour = 53
    sytle.pattern = pattern
#####################################################################################################################
    old_data = xlrd.open_workbook("模板生成\省公司内网现存中高危漏洞统计情况.xls")#上周生成的周报数据
    sheet1 = old_data.sheet_by_name("Sheet1")
    the_length1 = sheet1.nrows
    list_old_system = []
    list_old_number = []
    list_old_asset = []
    list_old_mail = []
    list_old_user = []
    title = [
        "部门",
        "科室",
        "系统",
        "负责人",
        "负责人邮箱",
        "系统主机数量",
        "上周可整改未整改漏洞（中+高）",
        "当前可整改未整改漏洞（中+高）",
        "本周整改数量(负增正减）"
    ]

    for each in range(the_length1):
        if each >= 1:
            system = sheet1.cell_value(each,2).replace("\r\n","")
            number = int(sheet1.cell_value(each,7))
            asset = int(sheet1.cell_value(each,5))
            mail = str(sheet1.cell_value(each,4))
            user = str(sheet1.cell_value(each,3))
            list_old_system.append(system)
            list_old_number.append(number)
            list_old_asset.append(asset)
            list_old_mail.append(mail)
            list_old_user.append(user)
            print(system,user,mail,number)

    write_data = xlwt.Workbook()
    table2 = write_data.add_sheet("Sheet1",cell_overwrite_ok=True)

    for x in range(len(title)):
        table2.write(0,x,title[x],sytle)

    for index1,data1 in enumerate(list_old_system):
        table2.write(index1+1,2,data1,sytle2)
        table2.write(index1+1,6,list_old_number[index1],sytle1)
        for index2,data2 in enumerate(yewuxitong):
            if data1 == data2:
                table2.write(index1+1,0,bumeng[index2],sytle1)
                table2.write(index1+1,1,keshi[index2],sytle1)
                table2.write(index1+1,7,exploits[index2],sytle1)
                table2.write(index1+1,3,fuzeren[index2],sytle2)
                table2.write(index1+1,5,list_old_asset[index1],sytle1)
                table2.write(index1+1,8,list_old_number[index1]-exploits[index2],sytle1)
            else:
                pass
            if list_old_user[index1] == fuzeren[index2]:
                table2.write(index1+1,4,list_old_mail[index1],sytle2)
            else:
                pass
    name = "省公司现存中高危漏洞统计情况"+str(today)+".xls"
    write_data.save(name)

    #生成模板数据，用于填写周报报告数据。
    mobandata = xlrd.open_workbook(name)
    mobandata_table = mobandata.sheet_by_index(0)
    data_len = mobandata_table.nrows
    list_all_data = []

    for each_row in range(data_len):
        list_all_data.append(mobandata_table.row_values(each_row))

    def info_zhenggai(every_data,sum):
        info = f"""（{sum}）完成{every_data[2]}统复查：本周整改漏洞数量{int(abs(every_data[8]))}个，剩余{int(every_data[7])}个。系统责任人：{every_data[0]} {every_data[1]} {every_data[3]}"""
        return info

    def info_xinzeng(every_data,sum):
        info  = f"""（{sum}）完成{every_data[2]}统复查：本周新增漏洞数量{int(abs(every_data[8]))}个，剩余{int(every_data[7])}个。系统责任人：{every_data[0]} {every_data[1]} {every_data[3]}"""
        return info

    list_shichangbu = []
    list_zhengqibg = []
    list_qudaoyuying = []
    list_quankehuyuying = []
    list_shuchuangzhongxin = []
    sum_shichangbu = 1
    sum_zhengqibg = 1
    sum_quankehu = 1
    sum_qudaoyuying = 1
    sum_shuchuangzhongxin = 1

    for every_data in list_all_data:
        try:
            if every_data[0] == "市场部":
                if every_data[8] > 0:
                    print(every_data)
                    list_shichangbu.append(info_zhenggai(every_data,sum_shichangbu))
                    count = 1
                    sum_shichangbu = sum_shichangbu + count
                elif every_data[8] < 0:
                    list_shichangbu.append(info_xinzeng(every_data,sum_shichangbu))
                    print(every_data)
                    count = 1
                    sum_shichangbu = sum_shichangbu + count
            elif every_data[0] == "政企BG":
                if every_data[8] > 0:
                    list_zhengqibg.append(info_zhenggai(every_data,sum_zhengqibg))
                    print(every_data)
                    count = 1
                    sum_zhengqibg = sum_zhengqibg + count
                elif every_data[8] < 0:
                    list_zhengqibg.append(info_xinzeng(every_data,sum_zhengqibg))
                    print(every_data)
                    count = 1
                    sum_zhengqibg = sum_zhengqibg + count      
            elif every_data[0] == "全客户运营中心":
                if every_data[8] > 0:
                    list_quankehuyuying.append(info_zhenggai(every_data,sum_quankehu))
                    print(every_data)
                    count = 1
                    sum_quankehu = sum_quankehu + count
                elif every_data[8] < 0:
                    list_quankehuyuying.append(info_xinzeng(every_data,sum_quankehu))
                    count = 1
                    sum_quankehu = sum_quankehu + count
                    print(every_data)
            elif every_data[0] == "渠道运营中心":
                if every_data[8] > 0:
                    list_qudaoyuying.append(info_zhenggai(every_data,sum_qudaoyuying))
                    print(every_data)
                    count = 1
                    sum_qudaoyuying = sum_qudaoyuying + count
                elif every_data[8] < 0:
                    list_qudaoyuying.append(info_xinzeng(every_data,sum_qudaoyuying))
                    print(every_data)
                    count = 1
                    sum_qudaoyuying = sum_qudaoyuying + count
            else:
                if every_data[8] > 0:
                    list_shuchuangzhongxin.append(info_zhenggai(every_data,sum_shuchuangzhongxin))
                    print(every_data)
                    count = 1
                    sum_shuchuangzhongxin = sum_shuchuangzhongxin + count
                elif every_data[8] < 0:
                    list_shuchuangzhongxin.append(info_xinzeng(every_data,sum_shuchuangzhongxin))
                    print(every_data)
                    count = 1
                    sum_shuchuangzhongxin = sum_shuchuangzhongxin + count
        finally:
            continue

    for data in list_shichangbu:
        with open("mobansheng.txt","a+",encoding="utf-8") as f:
            f.write(data)
            f.write("\n")
    for data in list_zhengqibg:
        with open("mobansheng.txt","a+",encoding="utf-8") as f:
            f.write(data)
            f.write("\n")
    for data in list_quankehuyuying:
        with open("mobansheng.txt","a+",encoding="utf-8") as f:
            f.write(data)
            f.write("\n")
    for data in list_qudaoyuying:
        with open("mobansheng.txt","a+",encoding="utf-8") as f:
            f.write(data)
            f.write("\n")
    for data in list_shuchuangzhongxin:
        with open("mobansheng.txt","a+",encoding="utf-8") as f:
            f.write(data)
            f.write("\n")

if __name__ == "__main__":
    generate()