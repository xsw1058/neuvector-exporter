# pylint: disable=missing-module-docstring
# pylint: disable=bare-except
# pylint: disable=too-many-statements
# pylint: disable=too-many-locals

# This script uses the neuvector api to get information which can be used by
# prometheus. It used the following library
# https://prometheus.github.io/client_python/

# ----------------------------------------
# Imports
# ----------------------------------------
import argparse
import base64
import json
import os
import signal
import sys
import time
import urllib3
import requests
from prometheus_client import start_http_server, Metric, REGISTRY

# ----------------------------------------
# Constants
# ----------------------------------------

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SESSION = requests.Session()
ENABLE_ENFORCER_STATS = False

# ----------------------------------------
# Functions
# ----------------------------------------

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
    return 0

# ----------------------------------------
# Classes
# ----------------------------------------


class NVApiCollector:
    """
    main api object
    """

    def __init__(self, endpoint, ctrl_user, ctrl_pass):
        """
        Initialize the object
        """
        self._endpoint = endpoint
        self._user = ctrl_user
        self._pass = ctrl_pass
        self._url = "https://" + endpoint

    def sigterm_handler(self, _signo, _stack_frame):
        """
        Logout when terminated
        """
        print("Logout ...")
        SESSION.delete(self._url + '/v1/auth')
        sys.exit(0)

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

    def collect(self):
        """
        Collect the required information
        This method is called by the library, for more information
        see https://prometheus.io/docs/instrumenting/writing_clientlibs/#overall-structure
        """
        eps = self._endpoint.split(':')
        ep = eps[0]

        # Get system summary
        response = self.get('/v1/system/summary')
        if response:
            sjson = json.loads(response.text)
            # Set summary metrics
            metric = Metric('nv_summary', 'A summary of ' + ep, 'summary')
            metric.add_sample('nv_summary_services',
                              value=sjson["summary"]["services"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_policy',
                              value=sjson["summary"]["policy_rules"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_runningWorkloads',
                              value=sjson["summary"]["running_workloads"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_totalWorkloads',
                              value=sjson["summary"]["workloads"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_hosts',
                              value=sjson["summary"]["hosts"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_controllers',
                              value=sjson["summary"]["controllers"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_enforcers',
                              value=sjson["summary"]["enforcers"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_pods',
                              value=sjson["summary"]["running_pods"],
                              labels={'target': ep})
            metric.add_sample('nv_summary_disconnectedEnforcers',
                              value=sjson["summary"]["disconnected_enforcers"],
                              labels={'target': ep})
            dt = sjson["summary"]["cvedb_create_time"]
            if not dt:
                metric.add_sample('nv_summary_cvedbVersion',
                                  value=1.0,
                                  labels={'target': ep})
            else:
                metric.add_sample('nv_summary_cvedbVersion',
                                  value=sjson["summary"]["cvedb_version"],
                                  labels={'target': ep})
            # Convert time, set CVEDB create time
            dt = sjson["summary"]["cvedb_create_time"]
            if not dt:
                metric.add_sample('nv_summary_cvedbTime',
                                  value=0,
                                  labels={'target': ep})
            else:
                ts = time.strptime(dt, '%Y-%m-%dT%H:%M:%SZ')
                metric.add_sample('nv_summary_cvedbTime',
                                  value=time.mktime(ts) * 1000,
                                  labels={'target': ep})
            yield metric

        # Get conversation
        response = self.get('/v1/conversation')
        if response:
            # Set conversation metrics
            metric = Metric('nv_conversation', 'conversation of ' + ep,
                            'gauge')
            for c in json.loads(response.text)['conversations']:
                try:
                    c['ports']
                except KeyError:
                    port_exists = False
                else:
                    port_exists = True
                if port_exists is True:
                    for k in c['ports']:
                        if c['bytes'] != 0:
                            metric.add_sample('nv_conversation_bytes',
                                              value=c['bytes'],
                                              labels={
                                                  'port': k,
                                                  'from': c['from'],
                                                  'to': c['to'],
                                                  'target': ep
                                              })
            yield metric

        # Get enforcer
        if ENABLE_ENFORCER_STATS:
            response = self.get('/v1/enforcer')
            if response:
                # Read each enforcer, set enforcer metrics
                metric = Metric('nv_enforcer', 'enforcers of ' + ep, 'gauge')
                for c in json.loads(response.text)['enforcers']:
                    response2 = self.get('/v1/enforcer/' + c['id'] + '/stats')
                    if response2:
                        ejson = json.loads(response2.text)
                        metric.add_sample('nv_enforcer_cpu',
                                          value=ejson['stats']['span_1']['cpu'],
                                          labels={
                                              'id': c['id'],
                                              'host': c['host_name'],
                                              'display': c['display_name'],
                                              'target': ep
                                          })
                        metric.add_sample('nv_enforcer_memory',
                                          value=ejson['stats']['span_1']['memory'],
                                          labels={
                                              'id': c['id'],
                                              'host': c['host_name'],
                                              'display': c['display_name'],
                                              'target': ep
                                          })
                yield metric

        # Get controller
        response = self.get('/v1/controller')
        if response:
            # Read each controller, set controller metrics
            metric = Metric('nv_controller', 'controllers of ' + ep, 'gauge')
            for c in json.loads(response.text)['controllers']:
                response2 = self.get('/v1/controller/' + c['id'] + '/stats')
                if response2:
                    ejson = json.loads(response2.text)
                    metric.add_sample('nv_controller_cpu',
                                      value=ejson['stats']['span_1']['cpu'],
                                      labels={
                                          'id': c['id'],
                                          'host': c['host_name'],
                                          'display': c['display_name'],
                                          'target': ep
                                      })
                    metric.add_sample('nv_controller_memory',
                                      value=ejson['stats']['span_1']['memory'],
                                      labels={
                                          'id': c['id'],
                                          'host': c['host_name'],
                                          'display': c['display_name'],
                                          'target': ep
                                      })
            yield metric

        # Get host
        response = self.get('/v1/host')
        if response:
            # Set host metrics
            metric = Metric('nv_host', 'host information of ' + ep, 'gauge')
            for c in json.loads(response.text)['hosts']:
                metric.add_sample('nv_host_memory',
                                  value=c['memory'],
                                  labels={
                                      'name': c['name'],
                                      'id': c['id'],
                                      'target': ep
                                  })
            yield metric

        # Get debug admission stats
        response = self.get('/v1/debug/admission_stats')
        if response:
            if response.status_code != 200:
                print("Admission control stats request failed: %s" % response)
            else:
                djson = json.loads(response.text)
                # Set admission metrics
                metric = Metric('nv_admission', 'Debug admission stats of ' + ep,
                                'gauge')
                metric.add_sample('nv_admission_allowed',
                                  value=djson['stats']['k8s_allowed_requests'],
                                  labels={'target': ep})
                metric.add_sample('nv_admission_denied',
                                  value=djson['stats']['k8s_denied_requests'],
                                  labels={'target': ep})
                yield metric

        # Get image vulnerability
        response = self.get('/v1/scan/registry')
        if response:
            # Set vulnerability metrics
            metric = Metric('nv_image_vulnerability',
                            'image vulnerability of ' + ep, 'gauge')
            for c in json.loads(response.text)['summarys']:
                response2 = self.get('/v1/scan/registry/' + c['name'] + '/images')
                if response2:
                    for img in json.loads(response2.text)['images']:
                        metric.add_sample('nv_image_vulnerabilityHigh',
                                          value=img['high'],
                                          labels={
                                              'name': "%s:%s" % (img['repository'], img['tag']),
                                              'imageid': img['image_id'],
                                              'target': ep
                                          })
                        metric.add_sample('nv_image_vulnerabilityMedium',
                                          value=img['medium'],
                                          labels={
                                              'name': "%s:%s" % (img['repository'], img['tag']),
                                              'imageid': img['image_id'],
                                              'target': ep
                                          })
            yield metric

        # Get platform vulnerability
        response = self.get('/v1/scan/platform/')
        if response:
            # Set vulnerability metrics
            metric = Metric('nv_platform_vulnerability',
                            'platform vulnerability of ' + ep, 'gauge')
            for platform in json.loads(response.text)['platforms']:
                if (platform['high'] != 0 or platform['medium'] != 0):
                    metric.add_sample('nv_platform_vulnerabilityHigh',
                                    value=platform['high'],
                                    labels={
                                        'name': platform['platform'],
                                        'target': ep
                                    })
                    metric.add_sample('nv_platform_vulnerabilityMedium',
                                    value=platform['medium'],
                                    labels={
                                        'name': platform['platform'],
                                        'target': ep
                                    })
            yield metric

        # Get container vulnerability
        response = self.get('/v1/workload?brief=true')
        if response:
            # Set vulnerability metrics
            cvlist = []
            metric = Metric('nv_container_vulnerability',
                            'container vulnerability of ' + ep, 'gauge')
            for c in json.loads(response.text)['workloads']:
                if c['service'] not in cvlist and c['service_mesh_sidecar'] is False:
                    scan = c['scan_summary']
                    if scan != None and (scan['high'] != 0 or scan['medium'] != 0):
                        metric.add_sample('nv_container_vulnerabilityHigh',
                                          value=scan['high'],
                                          labels={
                                              'service': c['service'],
                                              'target': ep
                                          })
                        metric.add_sample('nv_container_vulnerabilityMedium',
                                          value=scan['medium'],
                                          labels={
                                              'service': c['service'],
                                              'target': ep
                                          })
                        cvlist.append(c['service'])
            yield metric

        # Set Log metrics
        metric = Metric('nv_log', 'log of ' + ep, 'gauge')
        # Get log threat
        response = self.get('/v1/log/threat')
        if response:
            # Set threat
            ttimelist = []
            tnamelist = []
            tcnamelist = []
            tcnslist = []
            tsnamelist = []
            tsnslist = []
            tidlist = []
            for c in json.loads(response.text)['threats']:
                ttimelist.append(c['reported_timestamp'])
                tnamelist.append(c['name'])
                tcnamelist.append(c['client_workload_name'])
                tcnslist.append(c['client_workload_domain'] if 'client_workload_domain' in c else "")
                tsnamelist.append(c['server_workload_name'])
                tsnslist.append(c['server_workload_domain'] if 'server_workload_domain' in c else "")
                tidlist.append(c['id'])
            for x in range(0, min(5, len(tidlist))):
                metric.add_sample('nv_log_events',
                                  value=ttimelist[x] * 1000,
                                  labels={
                                      'log': "threat",
                                      'fromname': tcnamelist[x],
                                      'fromns': tcnslist[x],
                                      'toname': tsnamelist[x],
                                      'tons': tsnamelist[x],
                                      'id': tidlist[x],
                                      'name': tnamelist[x],
                                      'target': ep
                                  })

        # Get log incident
        response = self.get('/v1/log/incident')
        if response:
            # Set incident metrics
            itimelist = []
            inamelist = []
            iwnamelist = []
            iclusterlist = []
            iwnslist = []
            iwidlist = []
            iidlist = []
            iproc_name_list = []
            iproc_path_list = []
            iproc_cmd_list = []
            ifile_path_list = []
            ifile_name_list = []

            for c in json.loads(response.text)['incidents']:
                itimelist.append(c['reported_timestamp'])
                iidlist.append(c['id'])
                inamelist.append(c['name'])

                # Check proc_name
                if 'proc_name' in c:
                    iproc_name_list.append(c['proc_name'])
                else:
                    iproc_name_list.append("")

                # Check proc_path
                if 'proc_path' in c:
                    iproc_path_list.append(c['proc_path'])
                else:
                    iproc_path_list.append("")

                # Check proc_cmd
                if 'proc_cmd' in c:
                    iproc_cmd_list.append(c['proc_cmd'])
                else:
                    iproc_cmd_list.append("")

                # Check file_path
                if 'file_path' in c:
                    ifile_path_list.append(c['file_path'])
                else:
                    ifile_path_list.append("")

                # Check file_name
                if 'file_name' in c:
                    ifile_name_list.append(c['file_name'])
                else:
                    ifile_name_list.append("")

                if 'workload_name' in c:
                    iwnamelist.append(c['workload_name'])
                    iclusterlist.append(c['cluster_name'])
                    iwnslist.append(c['workload_domain'] if 'workload_domain' in c else "")
                    iwidlist.append(c['workload_id'])
                else:
                    iwnamelist.append("")
                    iclusterlist.append("")
                    iwnslist.append("")
                    iwidlist.append("")

            for x in range(0, min(5, len(iidlist))):
                metric.add_sample('nv_log_events',
                                  value=itimelist[x] * 1000,
                                  labels={
                                      'log': "incident",
                                      'fromname': iwnamelist[x],
                                      'fromns': iwnslist[x],
                                      'fromid': iwidlist[x],
                                      'toname': " ",
                                      'tons': " ",
                                      'cluster': iclusterlist[x],
                                      'name': inamelist[x],
                                      'id': iidlist[x],
                                      'procname': iproc_name_list[x],
                                      'procpath': iproc_path_list[x],
                                      'proccmd': iproc_cmd_list[x],
                                      'filepath': ifile_path_list[x],
                                      'filename': ifile_name_list[x],
                                      'target': ep
                                  })

        # Get log violation
        response = self.get('/v1/log/violation')
        if response:
            # Set violation metrics
            vtimelist = []
            vnamelist = []
            vcnamelist = []
            vcnslist = []
            vsnamelist = []
            vsnslist = []
            vidlist = []
            for c in json.loads(response.text)['violations']:
                vtimelist.append(c['reported_timestamp'])
                vcnamelist.append(c['client_name'])
                vcnslist.append(c['client_domain'] if 'client_domain' in c else "")
                vcidlist.append(c['client_id'])
                vnamelist.append("Network Violation")
                vsnamelist.append(c['server_name'])
                vsnslist.append(c['server_domain'] if 'server_domain' in c else "")
                vidlist.append(c['id'])
            for x in range(0, min(5, len(vidlist))):
                metric.add_sample('nv_log_events',
                                  value=vtimelist[x] * 1000,
                                  labels={
                                      'log': "violation",
                                      'id': vidlist[x],
                                      'fromname': vcnamelist[x],
                                      'fromns': vcnslist[x],
                                      'fromid': vcidlist[x],
                                      'toname': vsnamelist[x],
                                      'tons': vsnslist[x],
                                      'name': vnamelist[x],
                                      'target': ep
                                  })
            yield metric

        # Get federated information
        # Create nv_fed metric
        metric = Metric('nv_fed', 'log of ' + ep, 'gauge')

        # Get the api endpoint
        response = self.get('/v1/fed/member')

        # Check the respone
        if response:

            # Perform json load
            sjson = json.loads(response.text)

            # Check if the cluster is a federated master
            if sjson['fed_role'] == "master":

                # Set name of the master cluster
                fed_master_name = sjson['master_cluster']['name']

                # Loop through the list of nodes
                for fed_worker in sjson['joint_clusters']:

                    # Set status variable
                    if fed_worker['status'] != "synced":

                        # Set value to 0
                        fed_worker_value = 0

                    else:
                        fed_worker_value = 1

                    # Write the fed master metrics
                    metric.add_sample('nv_fed_master',
                                      value=fed_worker_value,
                                      labels={
                                          'master': fed_master_name,
                                          'worker': fed_worker['name'],
                                          'status': fed_worker['status']
                                      })
                yield metric

            # Add worker metrics
            else:

                # Write the worker metrics
                if sjson['fed_role'] != "joint":
                    fed_joint_status = 0
                else:
                    fed_joint_status = 1

                # Check if there is a master entry present
                if 'master_cluster' in sjson:
                    fed_master_cluster = sjson['master_cluster']['name']
                else:
                    fed_master_cluster = ""

                # Write the metrics
                metric.add_sample('nv_fed_worker',
                                  value=fed_joint_status,
                                  labels={
                                      'status': sjson['fed_role'],
                                      'master': fed_master_cluster
                                  })
                yield metric

class AutoJoiner:
    def __init__(self, join_token, join_token_url, endpoint, ctrl_user, ctrl_pass,
                 pass_store_id, ctrl_join_addr,ctrl_join_port,ctrl_join_addr_prefix,ctrl_join_addr_suffix,join_interval):
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
            if sjson['fed_role'] == "master" or sjson['fed_role'] == "joint":
                return False
        return True

    def try_join(self):
        while True:
            if self._join_token is None and self._join_token_url is None:
                print("join_token and join_token_url is None.")
                return
            if self._pass_store_id is None and self._ctrl_join_addr is None:
                print("pass_store_id and ctrl_join_addr is None.")
                return
            if self.need_to_join():
                print("---------------\nTrying join...")
                if self._join_token is None and not self.update_join_token():
                    print(f"join_token is None, and update join_token also failed, skip.")
                    return
                self.join_master()
                time.sleep(self._join_interval)
            else:
                time.sleep(self._join_interval * 5)

    def join_master(self):
        body = {"name":self._pass_store_id,"join_token":self._join_token,"joint_rest_info":{"server":self._ctrl_join_addr,"port":self._ctrl_join_port}}
        print(f"join request body: {json.dumps(body)}")
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
                print(f"join response body: {response.text}")
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
                print(f"get join_token from {self._join_token_url} success. parse result: server_addr is {server_addr}, server_port is {server_port}")
                self._join_token = join_token
                return True
            else:
                print(f"get join_token from {self._join_token_url} failed. status_code: {response.status_code}")
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

# 循环间隔
ENV_JOIN_INTERVAL = "JOIN_INTERVAL"
# 前缀
ENV_CTRL_JOIN_ADDR_PREFIX = "CTRL_JOIN_ADDR_PREFIX"
# 后缀
ENV_CTRL_JOIN_ADDR_SUFFIX = "CTRL_JOIN_ADDR_SUFFIX"

# test ENV
# os.environ[ENV_EXPORTER_PORT] = "9003"
# os.environ[ENV_CTRL_API_SVC] = "192.168.8.148:10443"
# os.environ[ENV_CTRL_USERNAME] = "admin"
# os.environ[ENV_CTRL_PASSWORD] = "admin"
# os.environ[ENV_CTRL_BOOTSTRAP_PASS] = "admin"
# os.environ[ENV_JOIN_TOKEN] = "eyJzIjoidTIyMDRhLnhzdy5jb20iLCJwIjo0NDMsInQiOiJFWWxqRk0vbDJpellHRmtoTklERXkxc1MwQklJcnRKdmpERUNWQjB5UUE5SFRIYjI5UzNXRVFabFdLVHJ1eDQ9In0="
# os.environ[ENV_JOIN_TOKEN_URL] = "http://u2204a.xsw.com/join_token"
# os.environ[ENV_PAAS_STORE_ID] = "u2204b"
# os.environ[ENV_CTRL_JOIN_ADDR_PREFIX] = ""
# os.environ[ENV_CTRL_JOIN_ADDR_SUFFIX] = ".xsw1.com"
# os.environ[ENV_JOIN_INTERVAL] = "3"
# os.environ[ENV_CTRL_JOIN_ADDR] = "u2204b.xsw.com"
# os.environ[ENV_CTRL_JOIN_PORT] = "xsw443"

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description='NeuVector command line.')
    PARSER.add_argument("-e", "--port", type=int, help="exporter port")
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

    if ARGSS.port:
        PORT = ARGSS.port
    elif ENV_EXPORTER_PORT in os.environ:
        PORT = int(os.environ.get(ENV_EXPORTER_PORT))
    else:
        sys.exit("Exporter port must be specified.")

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

    if ENV_ENFORCER_STATS in os.environ:
        try:
            ENABLE_ENFORCER_STATS = bool(os.environ.get(ENV_ENFORCER_STATS))
        except NameError:
            ENABLE_ENFORCER_STATS = False

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
        CTRL_JOIN_ADDR_PREFIX = "cn-wukong-"

    if ENV_CTRL_JOIN_ADDR_SUFFIX in os.environ:
        CTRL_JOIN_ADDR_SUFFIX = os.environ.get(ENV_CTRL_JOIN_ADDR_SUFFIX)
    else:
        CTRL_JOIN_ADDR_SUFFIX = ".mcd.store"

    if ENV_JOIN_INTERVAL in os.environ:
        JOIN_INTERVAL = os.environ.get(ENV_JOIN_INTERVAL)
    else:
        JOIN_INTERVAL = 30

    print(f"config:\n PORT={PORT}\n CTRL_SVC={CTRL_SVC}\n CTRL_USER={CTRL_USER}\n CTRL_PASS={CTRL_PASS[0:1]}*\n "
          f"CTRL_BOOTSTRAP_PASS={CTRL_BOOTSTRAP_PASS}\n "
          f"JOIN_TOKEN_URL={JOIN_TOKEN_URL}\n "
          f"JOIN_TOKEN={JOIN_TOKEN}\n "
          f"PAAS_STORE_ID={PAAS_STORE_ID}\n "
          f"CTRL_JOIN_ADDR={CTRL_JOIN_ADDR}\n "
          f"CTRL_JOIN_PORT={CTRL_JOIN_PORT}\n "
          f"CTRL_JOIN_ADDR_PREFIX={CTRL_JOIN_ADDR_PREFIX}\n "
          f"CTRL_JOIN_ADDR_SUFFIX={CTRL_JOIN_ADDR_SUFFIX}\n "
          f"JOIN_INTERVAL={JOIN_INTERVAL}\n ")

    joiner = None

    # 判断是否启用自动加入
    if PAAS_STORE_ID is None and CTRL_JOIN_ADDR is None:
        print("No PAAS_STORE_ID or CTRL_JOIN_ADDR specified. do not auto join.")
    elif JOIN_TOKEN is None and JOIN_TOKEN_URL is None:
        print("No JOIN_TOKEN or JOIN_TOKEN_URL specified. do not auto join.")
    else:
        joiner = AutoJoiner(JOIN_TOKEN, JOIN_TOKEN_URL, CTRL_SVC, CTRL_USER, CTRL_PASS,
                            PAAS_STORE_ID, CTRL_JOIN_ADDR, CTRL_JOIN_PORT,CTRL_JOIN_ADDR_PREFIX,CTRL_JOIN_ADDR_SUFFIX,JOIN_INTERVAL)

    # Login and get token
    if _login("https://" + CTRL_SVC, CTRL_USER, CTRL_PASS,CTRL_BOOTSTRAP_PASS) < 0:
        print(f"login failed: {CTRL_SVC}, exit after 300s.")
        time.sleep(300)
        sys.exit(1)

    print("Start exporter server ...")
    start_http_server(PORT)

    print("Register collector ...")
    COLLECTOR = NVApiCollector(CTRL_SVC, CTRL_USER, CTRL_PASS)
    REGISTRY.register(COLLECTOR)
    signal.signal(signal.SIGTERM, COLLECTOR.sigterm_handler)

    while True:
        if joiner :
            joiner.try_join()
        time.sleep(30)
