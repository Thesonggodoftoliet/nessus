import json
import logging
import threading
import time
import nacos
import pika
import polling
import requests
from flask import Flask
from flask import request

app = Flask(__name__)

SERVER_ADDRESSES = "http://192.168.0.108:8848"
NESSUS_URI = "https://192.168.0.108:8834"
NESSUS_HEADER = {'X-ApiKeys': "accessKey=be3690749e10f7f76a4c3e96f987984c741320c205916c0e13fe8f8d18a44dd6;"
                              "secretKey=fea7bd6c213224c973bffc7f1cca8cdf2dd6f0d227b72f65b976c81abccb0252;"}

MQ_HOST = "192.168.0.108"
MQ_PORT = 5672
MQ_USER = "cipc"
MQ_PASSWORD = "cipc9508"


@app.route('/scans/<scan_id>', methods=['GET'])
def detail_scan(scan_id):
    url = NESSUS_URI + "/scans/" + scan_id
    res = requests.get(url=url, headers=NESSUS_HEADER, verify=False)
    return res.json()


@app.route('/scans', methods=['POST'])
def create_scan():
    url = NESSUS_URI + "/scans"
    data = request.get_json()
    res = requests.post(url=url, headers=NESSUS_HEADER, verify=False, json=data['data'])
    return res.json()


@app.route('/scans/<scan_id>/launch', methods=['POST'])
def launch_scan(scan_id):
    url = NESSUS_URI + "/scans/" + scan_id + "/launch"
    res = requests.post(url=url, headers=NESSUS_HEADER, verify=False)
    print(res.json())
    # 启动轮询
    try:
        print(res.json()['scan_uuid'])
    except KeyError:
        print("出错")
    else:
        query_thread = threading.Thread(target=query_nessus_status, args=(scan_id,))
        query_thread.start()
    return res.json()


@app.route('/scans/<scan_id>/hosts/<host_id>', methods=['GET'])
def detail_host(scan_id, host_id):
    url = NESSUS_URI + "/scans/" + scan_id + "/hosts/" + host_id
    res = requests.get(url=url, headers=NESSUS_HEADER, verify=False)
    return res.json()


@app.route('/scans/<scan_id>/hosts/<host_id>/plugins/<plugin_id>', methods=['GET'])
def plugin_output(scan_id, host_id, plugin_id):
    url = NESSUS_URI + "/scans/" + scan_id + "/hosts/" + host_id + "/plugins/" + plugin_id
    res = requests.get(url=url, headers=NESSUS_HEADER, verify=False)
    return res.json()


@app.route('/settings/health/stats', methods=['GET'])
def get_status():
    url = NESSUS_URI + "/settings/health/stats"
    res = requests.get(url=url, headers=NESSUS_HEADER, verify=False)
    return res.json()


def health_stats():
    url = NESSUS_URI + "/settings/health/stats"
    res = requests.get(url=url, headers=NESSUS_HEADER, verify=False)
    return res.status_code == 200


def service_register():
    client = nacos.NacosClient(SERVER_ADDRESSES)
    client.add_naming_instance("nessus", "192.168.1.109", "8075")


def service_beat():
    client = nacos.NacosClient(SERVER_ADDRESSES)
    while True:
        if health_stats():
            client.send_heartbeat("nessus", "192.168.1.109", "8075")
            time.sleep(5)
        else:
            time.sleep(5)


def is_finish(response):
    # 检查扫描是否完成
    obj = json.loads(response.text)
    if obj['info']['status'] == 'completed':
        return True
    else:
        return False


@app.route("/publish/<scan_id>", methods=['GET'])
def query_nessus_status(scan_id=''):
    url = NESSUS_URI + "/scans/" + scan_id
    data = polling.poll(lambda: requests.get(url=url, headers=NESSUS_HEADER, verify=False),
                        check_success=is_finish, step=300, log=logging, poll_forever=True)
    obj = json.loads(data.text)
    messages = []
    for host in obj["hosts"]:
        temp = {}
        url = NESSUS_URI + "/scans/" + scan_id + "/hosts/" + str(host["host_id"])
        res = requests.get(url=url, headers=NESSUS_HEADER, verify=False)
        data = res.json()
        temp["ip"] = data["info"]["host-ip"]
        temp["os"] = data["info"]["operating-system"]
        temp["host_id"] = host["host_id"]
        if "netbios-name" in data["info"]:
            temp["host_name"] = data["info"]["netbios-name"]
        else:
            temp["host_name"] = ""
        if "mac-address" in data["info"]:
            temp["mac_address"] = data["info"]["mac-address"]
        else:
            temp["mac_address"] = ""
        vul_arr = []
        service_arr = []
        web_arr = []
        for vul in data["vulnerabilities"]:
            if (vul["plugin_family"] == "Service detection" or vul["plugin_family"] == "Web Servers" or
                    vul["plugin_family"] == "Databases"):
                if vul["severity"] == 0:
                    temp_data = plugin_output(scan_id, str(host["host_id"]), str(vul["plugin_id"]))
                    # 暂时只取了首个NESSUS输出
                    output = temp_data["outputs"][0]
                    attributes = str(output["plugin_output"]).split("\n")
                    ports = []
                    for port in output["ports"].keys():
                        ports.append(port)
                    tag = True
                    for attribute in attributes:
                        if attribute.__contains__("Version"):
                            version = attribute.split(":")
                            service = {"plugin_id": vul["plugin_id"], "version": version[1], "ports": ports}
                            service_arr.append(service)
                            tag = False
                            break
                    if tag is True:
                        service = {"plugin_id": vul["plugin_id"], "version": "unknown", "ports": ports}
                        service_arr.append(service)
            if vul["plugin_id"] == 24260:
                # webinfo
                host_name = "localhost"
                temp_data = plugin_output(scan_id, str(host["host_id"]), str(24260))
                for output in temp_data["outputs"]:
                    webinfo = {}
                    for port in output["ports"].keys():
                        webinfo["port"] = port.split("/")[0]
                        host_name = output["ports"].get(port, [{"hostname":"localhost"}])[0]["hostname"]
                    attributes = str(output["plugin_output"]).split("\n")
                    for attribute in attributes:
                        if attribute.__contains__("Response Code"):
                            response = attribute.split(":")
                            webinfo["code"] = response[1].strip().replace("\r","")
                        elif attribute.__contains__("Protocol version"):
                            protocol = attribute.split(":")
                            webinfo["protocol"] = protocol[1].strip()
                        elif attribute.__contains__("title"):
                            attribute = attribute.strip()
                            attribute = attribute.replace("<title>","")
                            attribute = attribute.replace("</title>","")
                            webinfo["title"] = attribute.strip()
                        elif attribute.__contains__("SSL"):
                            ssl = attribute.split(":")[1]
                            if ssl.strip() == "no":
                                uri = "http://" + host_name + ":"+webinfo["port"]
                                webinfo["uri"] = uri
                            else:
                                uri = "https://" + host_name+":"+webinfo["port"]
                                webinfo["uri"] = uri
                    web_arr.append(webinfo)
            # 在图形数据库中进行筛选
            vul_arr.append(vul["plugin_id"])
        temp["vuls"] = vul_arr
        temp["services"] = service_arr
        temp["webinfo"] = web_arr
        messages.append(temp)
    publish_nessus(json.dumps(messages))
    return json.dumps(messages)


# 将Nessus结果发布到消息队列，再由服务器写入数据库
def publish_nessus(message=''):
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host=MQ_HOST, port=MQ_PORT,
                                  credentials=pika.PlainCredentials(username=MQ_USER, password=MQ_PASSWORD))
    )
    channel = connection.channel()
    # channel.exchange_declare(exchange='nessus', exchange_type='direct')
    channel.basic_publish(exchange='nessus', routing_key='graph', body=message)


if __name__ == '__main__':
    if health_stats():
        service_register()
        threading.Timer(5, service_beat).start()
        app.run(host='0.0.0.0', port=8075, debug=True)
