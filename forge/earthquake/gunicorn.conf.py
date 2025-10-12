# -*- coding: utf-8 -*-
#
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0
#
# References:
# https://github.com/benoitc/gunicorn/blob/master/examples/example_config.py

# import multiprocessing

# Server socket
bind = "0.0.0.0:8000"

# 待处理连接数, 可以等待服务的客户端数量
# 超过此数量会导致客户端在尝试连接时出错, 这个值只在高负载服务器上才有影响
# backlog = 2048

# Worker processes
# 此服务器应保持活动状态以处理请求的工作进程数量
# 一个正整数, 通常在 2-4 x $(NUM_CORES)范围内
# workers = multiprocessing.cpu_count() * 2 + 1
workers = 2

# 工作进程的类型
# 默认的同步类应该可以处理大多数 "常规" 类型的工作负载
worker_class = 'sync'

# 对于eventlet和gevent工作类这限制了单个进程可以同时处理的最大客户端数量
# 一个正整数通常设置为 1000 左右
worker_connections = 1000

# 如果工作进程在此 * 秒内未通知主进程它将被终止并会生成一个新的工作进程来替换它
timeout = 30

# 一般设置在1-5秒范围内
keepalive = 5

# 每个工作进程在处理完指定数量的请求后平滑重启防止内存泄漏
# 设置工作器在重启前可处理的最大请求数
# https://docs.gunicorn.org/en/stable/settings.html#max-requests
max_requests = 1000

# 为max_requests添加一个随机抖动
# 这能确保所有工作进程不会在同一时刻重启避免服务瞬间中断
# https://docs.gunicorn.org/en/stable/settings.html#max-requests-jitter
max_requests_jitter = 100

# 安装一个跟踪函数 它会输出运行服务器时执行的每一行python代码
# True or False
spew = False

## Server mechanics

# 不以守护进程模式运行, 以便容器可以管理进程的生命周期
daemon = False

# 将环境变量传递给执行环境
# raw_env = [
#     'DJANGO_SECRET_KEY=something',
#     'SPAM=eggs',
# ]

pidfile = None
user = None
group = None
umask = 0
tmp_upload_dir = None

## Logging

loglevel = 'info' # string of "debug", "info", "warning", "error", "critical"
accesslog = '-' # 输出到标准输出
errorlog = '-'

# 自定义访问日志的格式
# 包含了客户端IP(h) 请求行(r) 状态码(s) 响应大小(b)等有用信息
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
