/*
 * This file handles the core frontend logic for the real time earthquake dashboard, including data fetching, map rendering, ui updates, and theme control.
 *
 * Copyright (c) 2025 honeok <i@honeok.com>
 * SPDX-License-Identifier: Apache-2.0
 */

declare const L: any;

interface Earthquake {
  time: number;
  title: string;
  mag: number;
  lat: number;
  lon: number;
  depth: number;
}

interface ApiResponse {
  earthquakes: Earthquake[];
  error?: string;
}

// 初始化地图视图, 并根据用户区域动态选择服务器
const map = L.map('map').setView([0, 0], 2);
const isChina = navigator.language.startsWith('zh');
const tileUrl = isChina
  ? 'http://webst0{1-4}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x={x}&y={y}&z={z}'
  : 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';
const attribution = isChina ? '&copy; 高德地图 & OpenStreetMap contributors' : '&copy; OpenStreetMap contributors';
const tileLayer = L.tileLayer(tileUrl, { attribution }).addTo(map);

// 缓存DOM元素引用以提升性能
let markers: any[] = [];
const eventList: HTMLElement = document.getElementById('event-list')!;
const eventCount: HTMLElement = document.getElementById('event-count')!;
const updateTime: HTMLElement = document.getElementById('update-time')!;

/*
 * 从后端API获取地震数据
 * 附加时间戳参数以"破坏缓存" 确保每次调用都获取最新数据
 */
async function fetchEarthquakes(): Promise<ApiResponse> {
  try {
    const url = `/api/earthquakes?timestamp=${new Date().getTime()}`;
    const response = await fetch(url);
    if (!response.ok) throw new Error('API Error');
    return await response.json();
  } catch (error) {
    console.error('Fetch failed:', error);
    return { earthquakes: [], error: (error as Error).message };
  }
}

/*
 * 将地震数据渲染到视图, 包括地图和事件列表
 * 自动将时间戳本地化为用户浏览器所在时区的时间
 */
function updateMapAndList(data: ApiResponse): void {
  // 渲染新标记前先从地图上清除旧标记
  markers.forEach(marker => map.removeLayer(marker));
  markers = [];
  eventList.innerHTML = data.error ? `<p class="text-danger">加载失败: ${data.error}</p>` : '';

  if (data.earthquakes.length === 0 && !data.error) {
    eventList.innerHTML = '<p class="text-muted">过去24小时内无地震数据（min 2.5级）</p>';
    eventCount.textContent = '0';
    updateTime.textContent = new Date().toLocaleString();
    map.setView([0, 0], 2);
    return;
  }

  eventList.innerHTML = ''; // 填充新数据前确保列表已被清空

  data.earthquakes.forEach((eq: Earthquake) => {
    const timeStr = new Date(eq.time).toLocaleString();
    const row = document.createElement('div');
    row.className = 'event-item';
    row.innerHTML = `
            <strong>${eq.title}</strong><br>
            <small>时间: ${timeStr} | 震级: ${eq.mag} | 深度: ${eq.depth.toFixed(1)}km</small>
        `;
    eventList.appendChild(row);

    const radius = Math.max(5, eq.mag * 3);
    const color = eq.mag > 6 ? 'red' : eq.mag > 4 ? 'orange' : 'yellow';
    const marker = L.circleMarker([eq.lat, eq.lon], {
      radius: radius,
      fillColor: color,
      color: '#000',
      weight: 1,
      opacity: 1,
      fillOpacity: 0.8
    }).addTo(map);
    marker.bindPopup(`<b>${eq.title}</b><br>震级: ${eq.mag}<br>时间: ${timeStr}<br>深度: ${eq.depth.toFixed(1)}km`);
    markers.push(marker);
  });

  if (data.earthquakes.length > 0) {
    const group = new L.featureGroup(markers);
    // 确保在地图图层加载完成后再执行自适应缩放
    map.once('load', function () {
      map.fitBounds(group.getBounds().pad(0.1));
    });
    // 重新计算地图尺寸
    map.invalidateSize();
  }

  // 使用最新的数据数量和时间戳更新UI
  eventCount.textContent = data.earthquakes.length.toString();
  updateTime.textContent = new Date().toLocaleString();
}

/*
 * 主题管理
 * 处理主题切换 (浅色/深色/自动) 并持久化用户选择
 */
const themeSwitcher = document.getElementById('theme-switcher')!;
const themeIcon = document.getElementById('theme-icon')!;
const themeText = document.getElementById('theme-text')!;
const themeOptions = document.querySelectorAll('[data-theme-value]');

const themeMap: { [key: string]: { icon: string; text: string } } = {
  light: { icon: 'bi-sun-fill', text: '浅色' },
  dark: { icon: 'bi-moon-stars-fill', text: '深色' },
  auto: { icon: 'bi-circle-half', text: '系统' }
};

const getSystemTheme = (): 'light' | 'dark' => {
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
};

const applyTheme = (theme: 'light' | 'dark'): void => {
  document.body.setAttribute('data-theme', theme);
};

const updateThemeUI = (theme: string): void => {
  const { icon, text } = themeMap[theme];
  themeIcon.className = `bi ${icon}`;
  themeText.textContent = text;
};

const handleThemeChange = (theme: string): void => {
  if (theme === 'auto') {
    applyTheme(getSystemTheme());
    localStorage.removeItem('theme');
  } else {
    applyTheme(theme as 'light' | 'dark');
    localStorage.setItem('theme', theme);
  }
  updateThemeUI(theme);
};

const initializeTheme = (): void => {
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme) {
    handleThemeChange(savedTheme);
  } else {
    handleThemeChange('auto');
  }
};

themeOptions.forEach(option => {
  option.addEventListener('click', () => {
    const themeValue = option.getAttribute('data-theme-value');
    if (themeValue) {
      handleThemeChange(themeValue);
    }
  });
});

window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  const currentTheme = localStorage.getItem('theme');
  if (!currentTheme || currentTheme === 'auto') {
    handleThemeChange('auto');
  }
});

/*
 * 应用主入口
 * 初始化应用状态并设置周期性数据轮询
 */
function init(): void {
  eventList.innerHTML = '<p class="text-muted">正在加载数据...</p>';
  fetchEarthquakes().then(updateMapAndList);
  initializeTheme();

  // 设置轮询机制每2分钟刷新一次数据
  setInterval(() => {
    fetchEarthquakes().then(updateMapAndList);
  }, 120000);
}

init();
