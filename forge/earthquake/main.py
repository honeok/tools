#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Description: This implements the backend service for the real time earthquake dashboard, fetching the latest seismic data from the USGS.
#
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0

import os
import requests
from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

@app.route('/')
def index():
    earthquake_version = (os.environ.get('EARTHQUAKE_VERSION') or os.environ.get('earthquake_version') or 'none').lstrip('v')
    return render_template('index.html', earthquake_version=earthquake_version)

@app.route('/api/earthquakes')
def get_earthquakes():
    base_url = "https://earthquake.usgs.gov/fdsnws/event/1/query"

    """
    使用标准utc时间提供统一时间
    https://www.usgs.gov/faqs/what-utc-and-why-do-you-report-earthquakes-utc

    The default time reference on the Latest Earthquakes list is your local time based on the time clock on your computer or mobile device.
    最新地震列表中的默认时间参考是基于您计算机或移动设备上的时间钟的当地时间
    """

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)

    params = {
        'format': 'geojson',
        'starttime': start_time.isoformat(), # 使用24小时前的utc时间
        'endtime': end_time.isoformat(),     # 使用当前utc时间
        'limit': 100,
        'minmagnitude': 2.5,
        'orderby': 'time' # 按时间排序
    }
    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        response.encoding = 'utf-8'
        data = response.json()

        events = data.get('features', [])[:50]

        processed = []
        for event in events:
            props = event['properties']
            geom = event['geometry']['coordinates']
            processed.append({
                'time': props.get('time'),
                'title': props.get('title'),
                'mag': props.get('mag'),
                'lat': geom[1],
                'lon': geom[0],
                'depth': geom[2]
            })
        return jsonify({'earthquakes': processed})
    except Exception as e:
        return jsonify({'error': str(e), 'earthquakes': []}), 500
