# Prometheus exporter and Grafana template

![](nv_grafana.png)



### NV_Exporter Setup:
```bash
export REPO=registry.cn-hangzhou.aliyuncs.com/xsw1058
export TAG=v0.0.2
make push-image
```


#### To run the exporter as Python program
- Clone the repository
- Make sure you installed Python 3 and python3-pip:
```
$ sudo apt-get install python3
$ sudo apt-get install python3-pip
```
- Install the Prometheus Python client:
```
$ sudo pip3 install -U setuptools
$ sudo pip3 install -U pip
$ sudo pip3 install prometheus_client requests
```

##### Environment Variables

Variable | Description | Default 
-------- | ----------- | -------
`CTRL_API_SERVICE` | NeuVector controller REST API service endpoint | `nil` 
`CTRL_USERNAME` | Username to login to controller REST API service | `admin`
`CTRL_PASSWORD` | Password to login to controller REST API service | `admin`
```
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
```
