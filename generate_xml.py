import xml.etree.ElementTree as ET
from xml.dom import minidom
import random

def create_nmap_xml(filename='nmap_scan_test.xml', total_entries=2000, anomaly_count=5):
    """
    Nmap XML形式の架空データを生成する関数。
    
    Args:
        filename (str): 出力ファイル名。
        total_entries (int): 生成するポート情報の総数。
        anomaly_count (int): 意図的に異常として挿入するポートの数。
    """
    
    # ----------------------------------------------------
    # 1. データ定義（正常なデータとしてよくある組み合わせ）
    # ----------------------------------------------------
    
    # 標準的なIP範囲（架空）
    IP_BASE = "192.168.1."
    
    # 頻繁に開いているポートとサービスの組み合わせ (正常なデータ)
    NORMAL_PORTS = [
        (80, 'http', 'open'), (443, 'https', 'open'), (22, 'ssh', 'open'),
        (23, 'telnet', 'closed'), (25, 'smtp', 'filtered'), (53, 'domain', 'open'),
        (139, 'netbios-ssn', 'closed'), (445, 'microsoft-ds', 'closed'),
        (3389, 'ms-wbt-server', 'open'), (8080, 'http-proxy', 'open')
    ]
    
    # ----------------------------------------------------
    # 2. 異常なデータ（アノマリー）の定義
    # ----------------------------------------------------
    
    # アノマリーとして検出されやすい珍しいポートや状態
    ANOMALY_PORTS = [
        # 非常に珍しい、かつ開いているポート (アノマリーの核)
        (5555, 'unknown', 'open'), 
        # 開いているはずのないサービス名
        (21, 'http-proxy', 'open'),
        # 珍しい高位ポートが開いている
        (65123, 'unusual-svc', 'open'),
        # 特殊な状態
        (111, 'rpcbind', 'filtered'),
        # 標準ポートだが、通常とは違うサービス名
        (80, 'mysql', 'open')
    ]

    # ----------------------------------------------------
    # 3. XML構造の構築
    # ----------------------------------------------------
    
    root = ET.Element("nmaprun")
    
    host_count = 0
    port_entries = []

    # アノマリーデータを先にリストに挿入
    for port, service, state in ANOMALY_PORTS:
        ip = IP_BASE + str(random.randint(2, 254))
        port_entries.append((ip, str(port), 'tcp', state, service))
        host_count += 1
        
    # 残りのデータを正常データで埋める
    remaining_count = total_entries - anomaly_count
    for _ in range(remaining_count):
        port_id, service, state = random.choice(NORMAL_PORTS)
        ip = IP_BASE + str(random.randint(2, 254))
        port_entries.append((ip, str(port_id), 'tcp', state, service))
        host_count += 1

    # データをIPアドレスごとにグループ化（NmapのXML構造を再現）
    host_data = {}
    for ip, port, protocol, state, service in port_entries:
        if ip not in host_data:
            host_data[ip] = []
        host_data[ip].append((port, protocol, state, service))

    # XML要素の組み立て
    for ip, ports in host_data.items():
        host_elem = ET.SubElement(root, "host")
        ET.SubElement(host_elem, "status", state="up", reason="echo-reply")
        ET.SubElement(host_elem, "address", addr=ip, addrtype="ipv4")
        
        ports_elem = ET.SubElement(host_elem, "ports")
        
        for port_id, protocol, state, service in ports:
            port_elem = ET.SubElement(ports_elem, "port", protocol=protocol, portid=port_id)
            ET.SubElement(port_elem, "state", state=state, reason="syn-ack")
            ET.SubElement(port_elem, "service", name=service)

    # 4. 整形してファイルに書き出す
    rough_string = ET.tostring(root, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    
    with open(filename, "w", encoding="utf-8") as f:
        # 見やすいようにインデントをつけて保存
        f.write(reparsed.toprettyxml(indent="  "))
        
    print(f"✅ テスト用Nmap XMLファイル '{filename}' を {len(port_entries)} エントリで作成しました。")
    print(f"意図的に異常なデータが {anomaly_count} 個含まれています。")

# 実行
create_nmap_xml()