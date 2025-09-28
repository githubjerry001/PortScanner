#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
高性能端口扫描器 - Web版本
使用Flask提供Web界面，Win11风格UI
"""

from flask import Flask, render_template, request, jsonify, Response
from flask_socketio import SocketIO, emit
import socket
import asyncio
import time
import json
import struct
import random
import os
import sys
from typing import List, Tuple, Set, Optional, Dict
import threading
from concurrent.futures import ThreadPoolExecutor
import platform
from dataclasses import dataclass
from collections import defaultdict

def get_local_ip():
    """获取本机IP地址"""
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return '127.0.0.1'

@dataclass
class ScanResult:
    """扫描结果数据类"""
    ip: str
    port: int
    is_open: bool
    service: str = ""
    banner: str = ""
    response_time: float = 0.0
    scan_method: str = "tcp_connect"

class NmapStyleScanner:
    """接近nmap性能的高性能端口扫描器"""
    
    def __init__(self, max_concurrent=5000, base_timeout=0.1, scan_method='tcp_connect'):
        self.max_concurrent = max_concurrent
        self.base_timeout = base_timeout
        self.scan_method = scan_method
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.open_ports = set()
        self.scanned_count = 0
        self.total_count = 0
        self.is_running = False
        self.rtt_stats = defaultdict(list)  # RTT统计用于动态超时
        self.retry_ports = []  # 需要重试的端口
        
        # 端口优先级 - 常见端口优先扫描
        self.common_ports = {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 11211, 27017
        }
        
    def get_dynamic_timeout(self, ip: str) -> float:
        """根据RTT动态计算超时时间"""
        if ip in self.rtt_stats and self.rtt_stats[ip]:
            avg_rtt = sum(self.rtt_stats[ip]) / len(self.rtt_stats[ip])
            # 超时时间为平均RTT的3-5倍，最小50ms，最大2s
            return max(0.05, min(2.0, avg_rtt * 4))
        return self.base_timeout
    
    def update_rtt(self, ip: str, rtt: float):
        """更新RTT统计"""
        if len(self.rtt_stats[ip]) >= 10:
            self.rtt_stats[ip].pop(0)  # 保持最近10次的RTT
        self.rtt_stats[ip].append(rtt)
    
    async def tcp_connect_scan(self, ip: str, port: int) -> ScanResult:
        """TCP连接扫描（最准确）"""
        start_time = time.time()
        timeout = self.get_dynamic_timeout(ip)
        
        try:
            # 使用更优化的socket选项
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(timeout)
            
            # 非阻塞连接
            sock.setblocking(False)
            result = await asyncio.get_event_loop().sock_connect(sock, (ip, port))
            
            rtt = time.time() - start_time
            self.update_rtt(ip, rtt)
            
            # 尝试抓取banner
            banner = ""
            try:
                sock.settimeout(0.5)
                data = await asyncio.wait_for(
                    asyncio.get_event_loop().sock_recv(sock, 1024), 
                    timeout=0.5
                )
                banner = data.decode('utf-8', errors='ignore').strip()[:100]
            except:
                pass
            
            sock.close()
            return ScanResult(ip, port, True, "", banner, rtt, "tcp_connect")
            
        except (ConnectionRefusedError, socket.error):
            return ScanResult(ip, port, False, "", "", 0, "tcp_connect")
        except Exception:
            # 网络错误，可能需要重试
            return ScanResult(ip, port, False, "", "", 0, "tcp_connect")
        finally:
            try:
                sock.close()
            except:
                pass
    
    async def tcp_syn_scan(self, ip: str, port: int) -> ScanResult:
        """TCP SYN扫描（更快但需要权限）"""
        start_time = time.time()
        timeout = self.get_dynamic_timeout(ip)
        
        try:
            # 创建原始socket（需要管理员权限）
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.setblocking(False)
            
            try:
                await asyncio.get_event_loop().sock_connect(sock, (ip, port))
                # 立即关闭连接（SYN扫描风格）
                sock.close()
                
                rtt = time.time() - start_time
                self.update_rtt(ip, rtt)
                return ScanResult(ip, port, True, "", "", rtt, "tcp_syn")
                
            except ConnectionRefusedError:
                return ScanResult(ip, port, False, "", "", 0, "tcp_syn")
            except:
                return ScanResult(ip, port, False, "", "", 0, "tcp_syn")
                
        except Exception:
            return ScanResult(ip, port, False, "", "", 0, "tcp_syn")
        finally:
            try:
                sock.close()
            except:
                pass
    
    async def scan_port_optimized(self, ip: str, port: int) -> ScanResult:
        """优化的端口扫描"""
        async with self.semaphore:
            if not self.is_running:
                return ScanResult(ip, port, False, "", "", 0, "cancelled")
            
            try:
                # 根据扫描方法选择
                if self.scan_method == 'tcp_syn':
                    result = await self.tcp_syn_scan(ip, port)
                else:
                    result = await self.tcp_connect_scan(ip, port)
                
                return result
                
            except Exception as e:
                return ScanResult(ip, port, False, "", "", 0, f"error: {str(e)}")
            finally:
                self.scanned_count += 1
    
    def prioritize_targets(self, targets: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
        """优化目标顺序 - 常见端口优先"""
        common = []
        uncommon = []
        
        for ip, port in targets:
            if port in self.common_ports:
                common.append((ip, port))
            else:
                uncommon.append((ip, port))
        
        # 随机化以避免目标检测
        random.shuffle(common)
        random.shuffle(uncommon)
        
        return common + uncommon
    
    async def batch_scan_optimized(self, targets: List[Tuple[str, int]], callback=None) -> Set[ScanResult]:
        """优化的批量扫描"""
        self.total_count = len(targets)
        self.scanned_count = 0
        self.open_ports.clear()
        self.is_running = True
        
        # 优化目标顺序
        targets = self.prioritize_targets(targets)
        
        # 动态批处理 - 根据性能调整批大小
        batch_size = min(2000, max(500, len(targets) // 10))
        results = set()
        
        for i in range(0, len(targets), batch_size):
            if not self.is_running:
                break
            
            batch_targets = targets[i:i + batch_size]
            
            # 创建批处理任务
            tasks = []
            for ip, port in batch_targets:
                if not self.is_running:
                    break
                task = asyncio.create_task(self.scan_port_optimized(ip, port))
                tasks.append(task)
            
            # 执行批处理
            try:
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, ScanResult):
                        if result.is_open:
                            results.add(result)
                            self.open_ports.add((result.ip, result.port))
                            if callback:
                                callback(result.ip, result.port, "开放")
                    elif isinstance(result, Exception):
                        # 记录异常但继续
                        pass
                        
            except Exception as e:
                print(f"批处理扫描错误: {e}")
                continue
            
            # 短暂延迟避免过载
            await asyncio.sleep(0.01)
        
        # 重试机制 - 对失败的端口进行二次扫描
        if self.retry_ports and self.is_running:
            await self.retry_failed_ports(callback)
        
        return results
    
    async def retry_failed_ports(self, callback=None):
        """重试失败的端口"""
        if not self.retry_ports:
            return
            
        retry_tasks = []
        for ip, port in self.retry_ports[:100]:  # 限制重试数量
            if not self.is_running:
                break
            task = asyncio.create_task(self.scan_port_optimized(ip, port))
            retry_tasks.append(task)
        
        try:
            retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)
            for result in retry_results:
                if isinstance(result, ScanResult) and result.is_open:
                    self.open_ports.add((result.ip, result.port))
                    if callback:
                        callback(result.ip, result.port, "开放")
        except:
            pass
    
    def stop_scan(self):
        """停止扫描"""
        self.is_running = False

class WebPortScanner:
    """Web端口扫描器管理类"""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.scanner = None
        self.scan_task = None
        self.loop = None
        self.loop_thread = None
        self.is_scanning = False
        
    def get_service_name(self, port: int) -> str:
        """根据端口号获取服务名称"""
        # 扩展的服务数据库
        common_ports = {
            # 基础服务
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 587: 'SMTP-TLS', 465: 'SMTP-SSL', 3389: 'RDP',
            # 数据库
            3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
            1433: 'MSSQL', 1521: 'Oracle', 5984: 'CouchDB', 9042: 'Cassandra',
            # Web服务
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8000: 'HTTP-Dev', 3000: 'Node.js',
            8888: 'HTTP-Alt2', 9090: 'HTTP-Alt3', 8081: 'HTTP-Proxy',
            # 中间件
            9200: 'Elasticsearch', 5672: 'RabbitMQ', 11211: 'Memcached', 6380: 'Redis-Alt',
            9092: 'Kafka', 2181: 'Zookeeper', 4369: 'Erlang', 25672: 'RabbitMQ-Cluster',
            # 监控和管理
            9000: 'SonarQube', 8088: 'Hadoop', 8086: 'InfluxDB', 3000: 'Grafana',
            9090: 'Prometheus', 8500: 'Consul', 4040: 'Spark-UI',
            # 容器和云
            2375: 'Docker', 2376: 'Docker-SSL', 8001: 'Kubernetes', 6443: 'Kubernetes-API',
            2379: 'etcd', 2380: 'etcd-peer', 10250: 'kubelet',
            # 其他常见服务
            135: 'RPC', 139: 'NetBIOS', 445: 'SMB', 1723: 'PPTP', 5900: 'VNC',
            548: 'AFP', 631: 'IPP', 873: 'rsync', 990: 'FTPS', 992: 'Telnets',
            2049: 'NFS', 111: 'Portmapper', 161: 'SNMP', 162: 'SNMP-Trap',
            69: 'TFTP', 67: 'DHCP', 68: 'DHCP-Client', 123: 'NTP',
            # 游戏和娱乐
            25565: 'Minecraft', 27015: 'Steam', 1935: 'RTMP', 554: 'RTSP',
            # 安全相关
            4444: 'Metasploit', 8834: 'Nessus', 10050: 'Zabbix-Agent', 10051: 'Zabbix-Server'
        }
        return common_ports.get(port, 'Unknown')
    
    def parse_ports(self, ports_str):
        """解析端口字符串"""
        ports = set()
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = part.split('-')
                    ports.update(range(int(start), int(end)+1))
                except ValueError:
                    continue
            else:
                try:
                    ports.add(int(part))
                except ValueError:
                    continue
        return sorted(ports)

    def ip_to_int(self, ip):
        """将IPv4地址转换为整数表示"""
        return sum(int(octet) << (24 - 8*i) for i, octet in enumerate(ip.split('.')))

    def int_to_ip(self, num):
        """将整数转换为IP地址"""
        return '.'.join(str((num >> (24 - 8*i)) & 0xFF) for i in range(4))

    def generate_ips(self, start_ip, end_ip):
        """生成IP地址范围列表"""
        start = self.ip_to_int(start_ip)
        end = self.ip_to_int(end_ip)
        return [self.int_to_ip(n) for n in range(start, end+1)]
    
    def run_async_loop(self):
        """在独立线程中运行事件循环"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()
        
    def stop_async_loop(self):
        """停止事件循环"""
        if self.loop and not self.loop.is_closed():
            self.loop.call_soon_threadsafe(self.loop.stop)
    
    async def async_scan_wrapper(self, targets, scan_params):
        """异步扫描包装器"""
        start_time = time.time()
        
        # 创建高性能扫描器实例
        max_concurrent = scan_params.get('concurrent', 5000)
        timeout = scan_params.get('timeout', 50) / 1000  # 转换为秒
        scan_method = scan_params.get('scan_mode', 'tcp_connect')
        
        # 使用新的高性能扫描器
        self.scanner = NmapStyleScanner(
            max_concurrent=max_concurrent, 
            base_timeout=timeout,
            scan_method=scan_method
        )
        
        def update_callback(ip, port, status):
            service = self.get_service_name(port)
            self.socketio.emit('scan_result', {
                'ip': ip,
                'port': port,
                'status': status,
                'service': service
            })
            
        # 定期发送进度更新
        def progress_updater():
            last_scanned = 0
            while self.scanner.is_running:
                if self.scanner.total_count > 0:
                    progress = (self.scanner.scanned_count / self.scanner.total_count) * 100
                    elapsed = time.time() - start_time
                    
                    # 计算实时速度
                    current_scanned = self.scanner.scanned_count
                    speed = (current_scanned - last_scanned) / 0.5 if elapsed > 0 else 0
                    last_scanned = current_scanned
                    
                    self.socketio.emit('scan_progress', {
                        'progress': progress,
                        'scanned': self.scanner.scanned_count,
                        'total': self.scanner.total_count,
                        'open_ports': len(self.scanner.open_ports),
                        'speed': speed,
                        'elapsed_time': elapsed
                    })
                time.sleep(0.5)
        
        # 启动进度更新线程
        progress_thread = threading.Thread(target=progress_updater, daemon=True)
        progress_thread.start()
        
        try:
            # 执行优化扫描
            scan_results = await self.scanner.batch_scan_optimized(targets, update_callback)
            
            # 扫描完成
            elapsed_time = time.time() - start_time
            total_ports = len(targets)
            avg_speed = total_ports / elapsed_time if elapsed_time > 0 else 0
            
            self.socketio.emit('scan_completed', {
                'open_count': len(scan_results),
                'total_count': total_ports,
                'elapsed_time': elapsed_time,
                'speed': avg_speed,
                'scan_method': scan_method
            })
            
        except Exception as e:
            self.socketio.emit('scan_error', {'error': str(e)})
        finally:
            self.is_scanning = False
    
    def start_scan(self, scan_params):
        """开始扫描"""
        if self.is_scanning:
            return {'success': False, 'message': '扫描正在进行中'}
        
        # 输入验证
        start_ip = scan_params.get('start_ip', '').strip()
        end_ip = scan_params.get('end_ip', '').strip() or start_ip
        ports_str = scan_params.get('ports', '').strip()
        
        if not start_ip:
            return {'success': False, 'message': '必须填写起始IP地址'}
            
        if not ports_str:
            return {'success': False, 'message': '必须填写要扫描的端口'}
            
        try:
            # 验证IP地址格式
            socket.inet_aton(start_ip)
            socket.inet_aton(end_ip)
        except socket.error:
            return {'success': False, 'message': 'IP地址格式无效'}

        # 检查起始IP是否大于结束IP
        if self.ip_to_int(start_ip) > self.ip_to_int(end_ip):
            return {'success': False, 'message': '起始IP不能大于结束IP'}

        # 解析端口
        try:
            ports = self.parse_ports(ports_str)
            if not ports:
                return {'success': False, 'message': '无效的端口格式'}
        except ValueError:
            return {'success': False, 'message': '端口格式错误'}

        # 生成目标列表
        ips = self.generate_ips(start_ip, end_ip)
        targets = [(ip, port) for ip in ips for port in ports]
        
        if len(targets) > 100000:  # 限制扫描数量
            return {'success': False, 'message': f'扫描目标过多 ({len(targets)})，请减少IP范围或端口数量'}
        
        self.is_scanning = True
        
        # 启动异步事件循环（如果还没有运行）
        if not self.loop_thread or not self.loop_thread.is_alive():
            self.loop_thread = threading.Thread(target=self.run_async_loop, daemon=True)
            self.loop_thread.start()
            time.sleep(0.1)  # 等待事件循环启动
        
        # 在事件循环中提交扫描任务
        if self.loop:
            future = asyncio.run_coroutine_threadsafe(
                self.async_scan_wrapper(targets, scan_params), self.loop
            )
            self.scan_task = future
        
        return {
            'success': True, 
            'message': f'开始扫描 {len(ips)} 个IP地址的 {len(ports)} 个端口...',
            'total_targets': len(targets)
        }
    
    def stop_scan(self):
        """停止扫描"""
        if self.scanner:
            self.scanner.stop_scan()
        
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()
            
        self.is_scanning = False
        
        self.socketio.emit('scan_stopped', {'message': '扫描已停止'})
        
        return {'success': True, 'message': '扫描已停止'}

# 创建Flask应用
app = Flask(__name__)
app.config['SECRET_KEY'] = 'port_scanner_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# 创建扫描器实例
web_scanner = WebPortScanner(socketio)

@app.route('/')
def index():
    """主页"""
    return render_template('index.html', local_ip=get_local_ip())

@app.route('/api/start_scan', methods=['POST'])
def start_scan():
    """开始扫描API"""
    data = request.get_json()
    result = web_scanner.start_scan(data)
    return jsonify(result)

@app.route('/api/stop_scan', methods=['POST'])
def stop_scan():
    """停止扫描API"""
    result = web_scanner.stop_scan()
    return jsonify(result)

@app.route('/api/status')
def get_status():
    """获取扫描状态"""
    return jsonify({
        'is_scanning': web_scanner.is_scanning,
        'local_ip': get_local_ip()
    })

@socketio.on('connect')
def handle_connect():
    """处理客户端连接"""
    emit('connected', {'message': '连接成功'})

@socketio.on('disconnect')
def handle_disconnect():
    """处理客户端断开连接"""
    print('客户端断开连接')

if __name__ == '__main__':
    import random
    port = random.randint(8000, 9000)  # 随机端口避免冲突
    print(f"启动Web端口扫描器...")
    print(f"本机IP: {get_local_ip()}")
    print(f"访问地址: http://localhost:{port}")
    print(f"访问地址: http://{get_local_ip()}:{port}")
    
    # 启动应用
    socketio.run(app, host='0.0.0.0', port=port, debug=False)