# pylint: disable=missing-module-docstring
# pylint: disable=bare-except
# pylint: disable=too-many-statements
# pylint: disable=too-many-locals

# This script uses the neuvector api to auto join.

# ----------------------------------------
# Imports
# ----------------------------------------
import argparse
import base64
import datetime
import json
import os
import signal
import sys
import time
import urllib3
import requests

# ----------------------------------------
# Constants
# ----------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SESSION = requests.Session()

# ----------------------------------------
# Functions
# ----------------------------------------
def signal_handler(signal, frame):
    print('Caught Ctrl+C / SIGINT signal')
    sys.exit(0)

def _login(ctrl_url, ctrl_user, ctrl_pass, bootstrap_password):
    """
    Login to the api and get a token
    """
    print("Login to controller ...")
    body = {"password": {"username": ctrl_user, "password": ctrl_pass}}
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(ctrl_url + '/v1/auth',
                                 headers=headers,
                                 data=json.dumps(body),
                                 verify=False)
    except requests.exceptions.RequestException as login_error:
        print(login_error)
        return -1

    # print(response.text)
    # print(response.status_code)
    # maybe need to change password
    if (response.status_code == 401 or response.status_code == 408) and bootstrap_password is not None:
        print("login denied, try to change password.")
        body = {"password": {"username": ctrl_user, "password": bootstrap_password, "new_password": ctrl_pass}}
        try:
            response = requests.post(ctrl_url + '/v1/auth',
                                     headers=headers,
                                     data=json.dumps(body),
                                     verify=False,
                                     timeout=10)
        except requests.exceptions.RequestException as login_error:
            print(login_error)
            return -1

        if response.status_code == 200:
            print("change password success.")
        else:
            print("change password failed.")

    if response.status_code != 200:
        message = json.loads(response.text)["message"]
        print(message)
        return -1

    token = json.loads(response.text)["token"]["token"]

    # Update request session
    SESSION.headers.update({"Content-Type": "application/json"})
    SESSION.headers.update({'X-Auth-Token': token})
    print("Login to controller successfully.")
    return 0

# ----------------------------------------
# Classes
# ----------------------------------------

class AutoJoiner:
    def __init__(self, join_token, join_token_url, endpoint, ctrl_user, ctrl_pass,
                 pass_store_id, ctrl_join_addr,ctrl_join_port,ctrl_join_addr_prefix,ctrl_join_addr_suffix,join_interval,max_retry):
        self._endpoint = endpoint
        self._user = ctrl_user
        self._pass = ctrl_pass
        self._url = "https://" + endpoint
        self._join_token = join_token
        self._join_interval = int(join_interval)

        if join_token is not None and join_token_url is None:
            token_str = base64.b64decode(JOIN_TOKEN).decode("utf-8")
            server_addr = json.loads(token_str)["s"]
            server_port = json.loads(token_str)["p"]
            self._join_token_url = "https://" + server_addr + ":" + str(server_port) + "/join_token"
            print(f"generate join_token_url={self._join_token_url}")
        else:
            self._join_token_url = join_token_url

        if pass_store_id is not None and ctrl_join_addr is None:
            self._ctrl_join_addr = ctrl_join_addr_prefix + pass_store_id + ctrl_join_addr_suffix
            print(f"generate ctrl_join_addr={self._ctrl_join_addr}")
        else:
            self._ctrl_join_addr = ctrl_join_addr

        if ctrl_join_addr is not None and pass_store_id is None:
            s = str.removeprefix(ctrl_join_addr,ctrl_join_addr_prefix)
            self._pass_store_id = str.removesuffix(s,ctrl_join_addr_suffix)
            print(f"generate pass_store_id={self._pass_store_id}")
        else:
            self._pass_store_id = pass_store_id

        self._ctrl_join_port = int(ctrl_join_port)
        self._max_retry = int(max_retry)

    def get(self, path):
        """
        Function to perform the get operations
        inside the class
        """
        retry = 0
        while retry < 2:
            try:
                response = SESSION.get(self._url + path, verify=False)
            except requests.exceptions.RequestException as response_error:
                print(response_error)
                retry += 1
            else:
                if response.status_code == 401 or response.status_code == 408:
                    _login(self._url, self._user, self._pass,None)
                    retry += 1
                else:
                    return response

        print("Failed to GET " + path)
    def need_to_join(self):
        response = self.get('/v1/fed/member')
        if response:
            # Perform json load
            sjson = json.loads(response.text)
            # Check if the cluster is a federated master
            if sjson['fed_role'] == "master" :
                print("fed role is master, no need to join")
                return False
            if sjson['fed_role'] == "joint":
                if 'master_cluster' in sjson:
                    fed_master_cluster = sjson['master_cluster']['name']
                else:
                    fed_master_cluster = ""
                print(f"already joint '{fed_master_cluster}', no need to join")
                return False
        return True

    def try_join(self):
        for retry in range(1,self._max_retry+1):
            if self.need_to_join():
                print(f"------\n{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} attempt join {retry}/{self._max_retry}")
                if self._join_token is None and not self.update_join_token():
                    time.sleep(self._join_interval)
                    continue
                self.join_master()
            else:
                sys.exit(0)

        print(f"join retry {self._max_retry} failed. exiting.")
        sys.exit(1)

    def join_master(self):
        body = {"name":self._pass_store_id,"join_token":self._join_token,"joint_rest_info":{"server":self._ctrl_join_addr,"port":self._ctrl_join_port}}
        print(f"request body: {json.dumps(body)}")
        try:
            response = SESSION.post(self._url + "/v1/fed/join",
                                    data=json.dumps(body),
                                    verify=False)
        except requests.exceptions.RequestException as response_error:
            print(f"join error: {response_error}")
        else:
            if response.status_code == 200:
                token_str = base64.b64decode(self._join_token).decode("utf-8")
                server_addr = json.loads(token_str)["s"]
                server_port = json.loads(token_str)["p"]
                print(f"join to {server_addr}:{server_port} success!!!!!!")
                return 0
            else:
                print(f"response body: {response.text}\njoin failed. retry after update join token")
                self.update_join_token()

    def update_join_token(self):
        try:
            response = requests.get(self._join_token_url,
                                     verify=False)
            if response.status_code == 200:
                join_token = json.loads(response.text)["context"]
                token_str = base64.b64decode(join_token).decode("utf-8")
                server_addr = json.loads(token_str)["s"]
                server_port = json.loads(token_str)["p"]
                print(f"new join_token: {join_token}"
                      f" -> server_addr={server_addr}, server_port={server_port}.")
                self._join_token = join_token
                return True
            else:
                print(f"get join_token failed.\n"
                      f"join_token_url: {self._join_token_url}\n"
                      f"response.status_code: {response.status_code}\n"
                      f"response.text: {response.text}\n"
                      f"response.headers: {response.headers}")
        except Exception as e:
            print(f"try get join_token from {self._join_token_url}. panic: {e}")
        return False

ENV_CTRL_API_SVC = "CTRL_API_SERVICE"
ENV_CTRL_USERNAME = "CTRL_USERNAME"
ENV_CTRL_PASSWORD = "CTRL_PASSWORD"
ENV_EXPORTER_PORT = "EXPORTER_PORT"
ENV_ENFORCER_STATS = "ENFORCER_STATS"
# 以下环境变量为自动join主机群所需。
# 初始密码，如果存在且首次登录401时，则尝试更改密码。注意：如果此处的初始密码为默认密码，则更改无效。
ENV_CTRL_BOOTSTRAP_PASS = "CTRL_BOOTSTRAP_PASS"
# JOIN_TOKEN 和 JOIN_TOKEN_URL至少存在一个，否则不会自动join主集群。
ENV_JOIN_TOKEN = "JOIN_TOKEN"
# JOIN_TOKEN_URL 必须以http://或https://开头，并包含完整路径。
# 如果仅有JOIN_TOKEN，则会通过/join_token作为后缀构建JOIN_TOKEN_URL.
ENV_JOIN_TOKEN_URL = "JOIN_TOKEN_URL"
# 加入主机群时，PAAS_STORE_ID作为当前集群的名字。
# PAAS_STORE_ID 和 ENV_CTRL_JOIN_ADDR至少提供一个
ENV_PAAS_STORE_ID = "PAAS_STORE_ID"
# 暂未使用
ENV_CTRL_JOIN_NAME = "CTRL_JOIN_NAME"
# 加入主机群时，CTRL_JOIN_ADDR和CTRL_JOIN_PORT作为当前集群的controller的对外访问地址提交给master。
ENV_CTRL_JOIN_ADDR = "CTRL_JOIN_ADDR"
ENV_CTRL_JOIN_PORT = "CTRL_JOIN_PORT"
# 前缀
ENV_CTRL_JOIN_ADDR_PREFIX = "CTRL_JOIN_ADDR_PREFIX"
# 后缀
ENV_CTRL_JOIN_ADDR_SUFFIX = "CTRL_JOIN_ADDR_SUFFIX"

# 循环间隔
ENV_JOIN_INTERVAL = "JOIN_INTERVAL"
ENV_MAX_RETRY = "MAX_RETRY"

# test ENV
# os.environ[ENV_CTRL_API_SVC] = "192.168.8.149:10443"
# os.environ[ENV_CTRL_USERNAME] = "admin"
# os.environ[ENV_CTRL_PASSWORD] = "meRYADKoGU4JHJ7TQR"
# os.environ[ENV_CTRL_BOOTSTRAP_PASS] = "admin"
# os.environ[ENV_JOIN_TOKEN] = "eyJzIjoiY24td3Vrb25nLXJrZS11YXQwMS5tY2QuY2xvdWQiLCJwIjo0NDMsInQiOiJubkRKZ2JRY2RHdldaTXhqZk9YM2ZWS0w5cmpUU3o0c2plRU5CdU1FU00zM01taWNveXhmYnR4ZS9jdlhRQjg9In0="
# os.environ[ENV_JOIN_TOKEN_URL] = "https://cn-wukong-rke-uat01.mcd.cloud:443/join_token"
# os.environ[ENV_PAAS_STORE_ID] = "u2204b"
# os.environ[ENV_CTRL_JOIN_ADDR_PREFIX] = ""
# os.environ[ENV_CTRL_JOIN_ADDR_SUFFIX] = ".xsw1.com"
# os.environ[ENV_JOIN_INTERVAL] = "2"
# os.environ[ENV_MAX_RETRY] = "10"
# os.environ[ENV_CTRL_JOIN_ADDR] = "u2204b.xsw.com"
# os.environ[ENV_CTRL_JOIN_PORT] = "443"

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description='NeuVector command line.')
    PARSER.add_argument("-s",
                        "--server",
                        type=str,
                        help="controller API service")
    PARSER.add_argument("-u",
                        "--username",
                        type=str,
                        help="controller user name")
    PARSER.add_argument("-p",
                        "--password",
                        type=str,
                        help="controller user password")
    ARGSS = PARSER.parse_args()

    if ARGSS.server:
        CTRL_SVC = ARGSS.server
    elif ENV_CTRL_API_SVC in os.environ:
        CTRL_SVC = os.environ.get(ENV_CTRL_API_SVC)
    else:
        sys.exit("Controller API service endpoint must be specified.")

    if ARGSS.username:
        CTRL_USER = ARGSS.username
    elif ENV_CTRL_USERNAME in os.environ:
        CTRL_USER = os.environ.get(ENV_CTRL_USERNAME)
    else:
        CTRL_USER = "admin"

    if ARGSS.password:
        CTRL_PASS = ARGSS.password
    elif ENV_CTRL_PASSWORD in os.environ:
        CTRL_PASS = os.environ.get(ENV_CTRL_PASSWORD)
    else:
        CTRL_PASS = "admin"

    if ENV_CTRL_BOOTSTRAP_PASS in os.environ:
        CTRL_BOOTSTRAP_PASS = os.environ.get(ENV_CTRL_BOOTSTRAP_PASS)
    else:
        CTRL_BOOTSTRAP_PASS = None

    if ENV_JOIN_TOKEN_URL in os.environ:
        JOIN_TOKEN_URL = os.environ.get(ENV_JOIN_TOKEN_URL)
    else:
        JOIN_TOKEN_URL = None

    if ENV_JOIN_TOKEN in os.environ:
        JOIN_TOKEN = os.environ.get(ENV_JOIN_TOKEN)
    else:
        JOIN_TOKEN = None

    if ENV_PAAS_STORE_ID in os.environ:
        PAAS_STORE_ID = os.environ.get(ENV_PAAS_STORE_ID)
    else:
        PAAS_STORE_ID = None

    if ENV_CTRL_JOIN_ADDR in os.environ:
        CTRL_JOIN_ADDR = os.environ.get(ENV_CTRL_JOIN_ADDR)
    else :
        CTRL_JOIN_ADDR = None

    if ENV_CTRL_JOIN_PORT in os.environ:
        CTRL_JOIN_PORT = os.environ.get(ENV_CTRL_JOIN_PORT)
    else:
        CTRL_JOIN_PORT = 443

    if ENV_CTRL_JOIN_ADDR_PREFIX in os.environ:
        CTRL_JOIN_ADDR_PREFIX = os.environ.get(ENV_CTRL_JOIN_ADDR_PREFIX)
    else:
        CTRL_JOIN_ADDR_PREFIX = "cn-wukong-r"

    if ENV_CTRL_JOIN_ADDR_SUFFIX in os.environ:
        CTRL_JOIN_ADDR_SUFFIX = os.environ.get(ENV_CTRL_JOIN_ADDR_SUFFIX)
    else:
        CTRL_JOIN_ADDR_SUFFIX = ".mcd.store"

    if ENV_JOIN_INTERVAL in os.environ:
        JOIN_INTERVAL = os.environ.get(ENV_JOIN_INTERVAL)
    else:
        JOIN_INTERVAL = 30

    if ENV_MAX_RETRY in os.environ:
        MAX_RETRY = os.environ.get(ENV_MAX_RETRY)
    else:
        MAX_RETRY = 30

    print(f"config:\n CTRL_SVC={CTRL_SVC}\n CTRL_USER={CTRL_USER}\n CTRL_PASS={CTRL_PASS[0:1]}*\n "
          f"CTRL_BOOTSTRAP_PASS={CTRL_BOOTSTRAP_PASS}\n "
          f"JOIN_TOKEN_URL={JOIN_TOKEN_URL}\n "
          f"JOIN_TOKEN={JOIN_TOKEN}\n "
          f"PAAS_STORE_ID={PAAS_STORE_ID}\n "
          f"CTRL_JOIN_ADDR={CTRL_JOIN_ADDR}\n "
          f"CTRL_JOIN_PORT={CTRL_JOIN_PORT}\n "
          f"CTRL_JOIN_ADDR_PREFIX={CTRL_JOIN_ADDR_PREFIX}\n "
          f"CTRL_JOIN_ADDR_SUFFIX={CTRL_JOIN_ADDR_SUFFIX}\n "
          f"JOIN_INTERVAL={JOIN_INTERVAL}\n "
          f"MAX_RETRY={MAX_RETRY}\n ")

    # check var
    if PAAS_STORE_ID is None and CTRL_JOIN_ADDR is None:
        print("No PAAS_STORE_ID or CTRL_JOIN_ADDR specified. do not auto join.")
        sys.exit(1)
    elif JOIN_TOKEN is None and JOIN_TOKEN_URL is None:
        print("No JOIN_TOKEN or JOIN_TOKEN_URL specified. do not auto join.")
        sys.exit(1)

    joiner = AutoJoiner(JOIN_TOKEN, JOIN_TOKEN_URL, CTRL_SVC, CTRL_USER, CTRL_PASS,
                        PAAS_STORE_ID, CTRL_JOIN_ADDR, CTRL_JOIN_PORT,CTRL_JOIN_ADDR_PREFIX,CTRL_JOIN_ADDR_SUFFIX,JOIN_INTERVAL,MAX_RETRY)

    signal.signal(signal.SIGINT, signal_handler)
    # login
    for i in range(int(MAX_RETRY)):
        if _login("https://" + CTRL_SVC, CTRL_USER, CTRL_PASS, CTRL_BOOTSTRAP_PASS) < 0:
            print(f"login failed: {CTRL_SVC}, retry after {JOIN_INTERVAL}s.")
            time.sleep(int(JOIN_INTERVAL))
        else:
            break
        if i == int(MAX_RETRY)-1:
            print(f"login retry {i+1} failed. exiting.")
            sys.exit(1)

    joiner.try_join()
