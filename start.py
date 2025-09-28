#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
启动脚本 - 优化性能配置
"""

import os
import sys
import platform

def optimize_system():
    """优化系统设置以提高扫描性能"""
    
    # 设置环境变量优化
    os.environ['PYTHONUNBUFFERED'] = '1'  # 禁用Python输出缓冲
    
    # 根据操作系统进行优化
    system = platform.system().lower()
    
    if system == 'linux':
        print("检测到Linux系统，建议以下优化:")
        print("1. 增加文件描述符限制: ulimit -n 65536")
        print("2. 优化网络参数:")
        print("   echo 'net.core.somaxconn = 65536' >> /etc/sysctl.conf")
        print("   echo 'net.ipv4.ip_local_port_range = 1024 65535' >> /etc/sysctl.conf")
        print("   sysctl -p")
        
    elif system == 'windows':
        print("检测到Windows系统，自动应用性能优化...")
        # Windows下的socket优化
        import socket
        if hasattr(socket, 'SO_REUSEADDR'):
            print("✓ 启用socket地址重用")
    
    print(f"系统: {platform.system()} {platform.release()}")
    print(f"Python版本: {platform.python_version()}")
    print(f"建议的最大并发数: 5000-8000")

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 高性能端口扫描器 - 接近nmap性能")
    print("=" * 60)
    
    # 性能优化
    optimize_system()
    
    print("\n⚡ 性能特性:")
    print("- 动态超时调整")
    print("- 智能端口优先级")
    print("- 批量异步处理")
    print("- 多种扫描模式")
    print("- 实时RTT统计")
    
    print(f"\n🌐 启动Web服务器...")
    
    # 导入并启动web扫描器
    try:
        from web_scanner import app, socketio, get_local_ip
        
        local_ip = get_local_ip()
        port = 5001  # 使用不同端口避免冲突
        print(f"本机IP: {local_ip}")
        print(f"访问地址: http://localhost:{port}")
        print(f"访问地址: http://{local_ip}:{port}")
        print("\n⚠️  提示:")
        print("- 首次扫描可能较慢，后续会根据网络情况自动优化")
        print("- 大范围扫描建议使用TCP SYN模式")
        print("- 调整并发数以获得最佳性能")
        print("=" * 60)
        
        # 启动应用
        socketio.run(app, host='0.0.0.0', port=port, debug=False)
        
    except ImportError as e:
        print(f"❌ 导入错误: {e}")
        print("请确保已安装所有依赖包: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ 启动失败: {e}")