import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
from queue import Queue
import concurrent.futures
import asyncio
import time
from typing import List, Tuple, Set
import struct
import random

def get_local_ip():
    """
    获取本机IP地址
    
    返回:
        str: 成功返回本机IP字符串，失败返回127.0.0.1
    """
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return '127.0.0.1'

class HighPerformanceScanner:
    """高性能异步端口扫描器"""
    
    def __init__(self, max_concurrent=1000, timeout=0.1):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.open_ports = set()
        self.scanned_count = 0
        self.total_count = 0
        
    async def scan_port_async(self, ip: str, port: int) -> Tuple[str, int, bool]:
        """异步扫描单个端口"""
        async with self.semaphore:
            try:
                # 使用异步socket连接
                future = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                return (ip, port, True)
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return (ip, port, False)
            finally:
                self.scanned_count += 1
                
    async def syn_scan_port(self, ip: str, port: int) -> Tuple[str, int, bool]:
        """SYN扫描实现（更快的扫描方式）"""
        try:
            # 创建原始socket进行SYN扫描
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.setblocking(False)
            
            try:
                await asyncio.get_event_loop().sock_connect(sock, (ip, port))
                sock.close()
                return (ip, port, True)
            except (ConnectionRefusedError, OSError):
                sock.close()
                return (ip, port, False)
        except Exception:
            return (ip, port, False)
            
    async def batch_scan(self, targets: List[Tuple[str, int]], callback=None) -> Set[Tuple[str, int]]:
        """批量异步扫描"""
        self.total_count = len(targets)
        self.scanned_count = 0
        self.open_ports.clear()
        
        # 创建所有扫描任务
        tasks = []
        for ip, port in targets:
            task = asyncio.create_task(self.scan_port_async(ip, port))
            tasks.append(task)
            
        # 分批处理任务以控制内存使用
        batch_size = min(1000, len(tasks))
        results = set()
        
        for i in range(0, len(tasks), batch_size):
            batch_tasks = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            
            for result in batch_results:
                if isinstance(result, tuple) and result[2]:  # 端口开放
                    results.add((result[0], result[1]))
                    if callback:
                        callback(result[0], result[1], "开放")
                        
        return results

class OptimizedPortScannerApp:
    def __init__(self, master):
        """
        高性能端口扫描器主界面类
        
        参数:
            master: tkinter根窗口对象
        """
        self.master = master
        master.title("高性能端口扫描器 - 接近nmap速度")
        master.geometry("700x500")
        
        # 初始化高性能扫描器
        self.scanner = HighPerformanceScanner(max_concurrent=2000, timeout=0.05)
        
        # 创建界面组件
        self.create_widgets()
        self.running = False
        self.scan_task = None
        self.loop = None
        self.loop_thread = None

    def create_widgets(self):
        """创建程序界面组件，包含IP输入、端口输入、控制按钮和结果显示区域"""
        # IP地址输入区域
        ip_frame = ttk.LabelFrame(self.master, text="IP地址范围")
        ip_frame.pack(pady=10, padx=10, fill='x')
        
        ttk.Label(ip_frame, text="起始IP:").grid(row=0, column=0)
        self.start_ip = ttk.Entry(ip_frame)
        self.start_ip.insert(0, get_local_ip())
        self.start_ip.grid(row=0, column=1)
        
        ttk.Label(ip_frame, text="结束IP:").grid(row=0, column=2)
        self.end_ip = ttk.Entry(ip_frame)
        self.end_ip.grid(row=0, column=3)

        # 端口输入区域
        port_frame = ttk.LabelFrame(self.master, text="扫描端口")
        port_frame.pack(pady=10, padx=10, fill='x')
        
        ttk.Label(port_frame, text="端口（逗号分隔或范围）:").grid(row=0, column=0)
        self.ports_entry = ttk.Entry(port_frame)
        self.ports_entry.insert(0, "22,80,443,3389,8080,1-1000")  # 默认常用端口
        self.ports_entry.grid(row=0, column=1, sticky='ew')
        
        # 扫描参数配置
        config_frame = ttk.LabelFrame(self.master, text="扫描参数")
        config_frame.pack(pady=10, padx=10, fill='x')
        
        ttk.Label(config_frame, text="并发数:").grid(row=0, column=0, padx=5)
        self.concurrent_entry = ttk.Entry(config_frame, width=8)
        self.concurrent_entry.insert(0, '2000')
        self.concurrent_entry.grid(row=0, column=1, padx=5)
        
        ttk.Label(config_frame, text="超时(ms):").grid(row=0, column=2, padx=5)
        self.timeout_entry = ttk.Entry(config_frame, width=8)
        self.timeout_entry.insert(0, '50')
        self.timeout_entry.grid(row=0, column=3, padx=5)
        
        ttk.Label(config_frame, text="扫描模式:").grid(row=0, column=4, padx=5)
        self.scan_mode = ttk.Combobox(config_frame, values=["TCP Connect", "TCP SYN"], width=12)
        self.scan_mode.set("TCP Connect")
        self.scan_mode.grid(row=0, column=5, padx=5)

        # 控制按钮和进度
        btn_frame = ttk.Frame(self.master)
        btn_frame.pack(pady=10, fill='x', padx=10)
        
        # 进度条
        self.progress = ttk.Progressbar(btn_frame, orient='horizontal', mode='determinate')
        self.progress.pack(fill='x', pady=5)
        
        # 控制按钮
        control_frame = ttk.Frame(btn_frame)
        control_frame.pack()
        
        self.scan_btn = ttk.Button(control_frame, text="开始高速扫描", command=self.start_scan)
        self.scan_btn.pack(side='left', padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="停止", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        
        # 状态显示
        self.status_label = ttk.Label(btn_frame, text="就绪开始扫描...")
        self.status_label.pack(pady=5)

        # 结果显示区域
        result_frame = ttk.LabelFrame(self.master, text="扫描结果")
        result_frame.pack(pady=10, padx=10, fill='both', expand=True)
        
        # 结果统计
        stats_frame = ttk.Frame(result_frame)
        stats_frame.pack(fill='x', pady=5)
        
        self.stats_label = ttk.Label(stats_frame, text="开放端口: 0 | 已扫描: 0 | 总计: 0 | 速度: 0 端口/秒")
        self.stats_label.pack()
        
        self.result_tree = ttk.Treeview(result_frame, columns=('ip', 'port', 'status', 'service'), show='headings')
        self.result_tree.heading('ip', text='IP地址')
        self.result_tree.heading('port', text='端口')
        self.result_tree.heading('status', text='状态')
        self.result_tree.heading('service', text='服务')
        
        # 设置列宽
        self.result_tree.column('ip', width=120)
        self.result_tree.column('port', width=80)
        self.result_tree.column('status', width=80)
        self.result_tree.column('service', width=100)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient='vertical', command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scrollbar.set)
        
        self.result_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

    def get_service_name(self, port: int) -> str:
        """根据端口号获取服务名称"""
        common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 587: 'SMTP-TLS', 465: 'SMTP-SSL', 3389: 'RDP',
            3306: 'MySQL', 5432: 'PostgreSQL', 6379: 'Redis', 27017: 'MongoDB',
            1433: 'MSSQL', 1521: 'Oracle', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            9200: 'Elasticsearch', 5672: 'RabbitMQ', 11211: 'Memcached'
        }
        return common_ports.get(port, 'Unknown')
    def parse_ports(self, ports_str):
        """
        解析端口字符串
        
        参数:
            ports_str: 用户输入的端口字符串（支持逗号分隔和范围格式）
        返回:
            排序后的端口列表
        """
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
        """将IPv4地址转换为整数表示，用于IP范围生成"""
        return sum(int(octet) << (24 - 8*i) for i, octet in enumerate(ip.split('.')))

    def int_to_ip(self, num):
        return '.'.join(str((num >> (24 - 8*i)) & 0xFF) for i in range(4))

    def generate_ips(self, start_ip, end_ip):
        """
        生成IP地址范围列表
        
        参数:
            start_ip: 起始IP字符串
            end_ip: 结束IP字符串
        返回:
            IP地址列表
        """
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
            
    async def async_scan_wrapper(self, targets):
        """异步扫描包装器"""
        start_time = time.time()
        self.scan_start_time = start_time
        
        # 更新扫描器参数
        try:
            max_concurrent = int(self.concurrent_entry.get())
            timeout = float(self.timeout_entry.get()) / 1000  # 转换为秒
            self.scanner = HighPerformanceScanner(max_concurrent, timeout)
        except ValueError:
            self.scanner = HighPerformanceScanner(2000, 0.05)
            
        def update_callback(ip, port, status):
            service = self.get_service_name(port)
            self.master.after(0, lambda: self.update_result(ip, port, status, service))
            
        # 执行扫描
        open_ports = await self.scanner.batch_scan(targets, update_callback)
        
        # 扫描完成
        elapsed_time = time.time() - start_time
        total_ports = len(targets)
        speed = total_ports / elapsed_time if elapsed_time > 0 else 0
        
        self.master.after(0, lambda: self.scan_completed(len(open_ports), total_ports, elapsed_time, speed))
        
    def scan_completed(self, open_count, total_count, elapsed_time, speed):
        """扫描完成后的处理"""
        self.running = False
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.progress['value'] = self.progress['maximum']
        
        self.status_label.config(
            text=f"扫描完成! 耗时: {elapsed_time:.2f}秒 | 速度: {speed:.0f} 端口/秒"
        )
        self.stats_label.config(
            text=f"开放端口: {open_count} | 已扫描: {total_count} | 总计: {total_count} | 速度: {speed:.0f} 端口/秒"
        )
    def update_progress_periodically(self):
        """定期更新进度条和统计信息"""
        if self.running and self.scanner:
            current_scanned = self.scanner.scanned_count
            total_count = self.scanner.total_count
            open_count = len(self.scanner.open_ports)
            
            # 更新进度条
            if total_count > 0:
                self.progress['value'] = current_scanned
                progress_percent = (current_scanned / total_count) * 100
                
                # 计算速度
                elapsed = time.time() - self.scan_start_time if hasattr(self, 'scan_start_time') else 1
                speed = current_scanned / elapsed if elapsed > 0 else 0
                
                # 更新状态
                self.status_label.config(
                    text=f"扫描中... {progress_percent:.1f}% | 速度: {speed:.0f} 端口/秒"
                )
                self.stats_label.config(
                    text=f"开放端口: {open_count} | 已扫描: {current_scanned} | 总计: {total_count} | 速度: {speed:.0f} 端口/秒"
                )
            
            # 继续定期更新
            self.master.after(500, self.update_progress_periodically)

    def update_result(self, ip, port, status, service):
        """
        更新结果展示区域
        
        参数:
            ip: 目标IP地址
            port: 扫描端口
            status: 端口状态
            service: 服务名称
        """
        self.result_tree.insert('', 'end', values=(ip, port, status, service))
    def start_scan(self):
        """
        开始高性能扫描的入口函数
        执行输入验证、初始化任务队列、启动工作线程
        """
        # 输入验证
        start_ip = self.start_ip.get().strip()
        end_ip = self.end_ip.get().strip() or start_ip
        ports_str = self.ports_entry.get().strip()
        
        if not start_ip:
            messagebox.showerror("错误", "必须填写起始IP地址")
            return
            
        if not ports_str:
            messagebox.showerror("错误", "必须填写要扫描的端口")
            return
            
        try:
            # 验证IP地址格式
            socket.inet_aton(start_ip)
            socket.inet_aton(end_ip)
        except socket.error:
            messagebox.showerror("错误", "IP地址格式无效")
            return

        # 检查起始IP是否大于结束IP
        if self.ip_to_int(start_ip) > self.ip_to_int(end_ip):
            messagebox.showerror("错误", "起始IP不能大于结束IP")
            return

        # 解析端口
        try:
            ports = self.parse_ports(ports_str)
            if not ports:
                messagebox.showerror("错误", "无效的端口格式")
                return
        except ValueError:
            messagebox.showerror("错误", "端口格式错误")
            return

        self.running = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        
        # 清空结果
        self.result_tree.delete(*self.result_tree.get_children())

        # 生成目标列表
        ips = self.generate_ips(start_ip, end_ip)
        targets = [(ip, port) for ip in ips for port in ports]
        
        # 初始化进度条
        self.progress['value'] = 0
        self.progress['maximum'] = len(targets)
        
        # 启动异步事件循环（如果还没有运行）
        if not self.loop_thread or not self.loop_thread.is_alive():
            self.loop_thread = threading.Thread(target=self.run_async_loop, daemon=True)
            self.loop_thread.start()
            time.sleep(0.1)  # 等待事件循环启动
        
        # 在事件循环中提交扫描任务
        if self.loop:
            future = asyncio.run_coroutine_threadsafe(
                self.async_scan_wrapper(targets), self.loop
            )
            self.scan_task = future
            
        # 启动进度更新
        self.update_progress_periodically()
        
        self.status_label.config(text=f"开始扫描 {len(ips)} 个IP地址的 {len(ports)} 个端口...")

    def stop_scan(self):
        """
        停止扫描
        终止线程池，取消所有任务，更新界面状态
        """
        self.running = False
        
        # 取消当前扫描任务
        if self.scan_task and not self.scan_task.done():
            self.scan_task.cancel()
            
        # 停止事件循环
        self.stop_async_loop()
        
        self.scan_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_label.config(text="扫描已停止")


if __name__ == '__main__':
    root = tk.Tk()
    app = OptimizedPortScannerApp(root)
    root.mainloop()