import xml.etree.ElementTree as ET
import pandas as pd

def analyze_nmap_xml(filename='nmap_scan_test.xml'):
    """
    Nmap XMLをパースして、出現頻度が低い（異常な）ポート/サービスを検出する
    """
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
    except FileNotFoundError:
        print(f"エラー: {filename} が見つかりません。先に生成スクリプトを実行してください。")
        return

    data = []

    # XMLの解析とフラット化
    for host in root.findall('host'):
        ip_address = host.find('address').get('addr')
        
        ports = host.find('ports')
        if ports is not None:
            for port in ports.findall('port'):
                port_id = int(port.get('portid'))
                protocol = port.get('protocol')
                
                state_elem = port.find('state')
                state = state_elem.get('state') if state_elem is not None else 'unknown'
                
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else 'unknown'
                
                data.append({
                    'IP': ip_address,
                    'Port': port_id,
                    'Protocol': protocol,
                    'State': state,
                    'Service': service,
                    'Signature': f"{port_id}/{service}" # ポートとサービスの組み合わせ
                })

    df = pd.DataFrame(data)

    print(f"--- 分析レポート: 総エントリー数 {len(df)} ---")

    # -------------------------------------------------------
    # 簡易的な異常検知ロジック: 出現頻度分析
    # -------------------------------------------------------
    
    # ポートとサービスの組み合わせ(Signature)ごとの出現回数をカウント
    signature_counts = df['Signature'].value_counts()
    
    # 全体の1%未満しか出現しないものを「異常（Anomaly）」とみなす
    threshold = len(df) * 0.01 
    anomalies = signature_counts[signature_counts < threshold]

    print(f"\n[検出された異常候補] (出現回数が {int(threshold)} 回未満の組み合わせ)")
    print("-" * 60)
    
    if len(anomalies) == 0:
        print("異常データは見つかりませんでした。")
    else:
        # 異常と判定されたSignatureを持つ行を抽出して表示
        rare_signatures = anomalies.index.tolist()
        result = df[df['Signature'].isin(rare_signatures)].sort_values(by='Port')
        
        # 表示を見やすく整形
        print(result[['IP', 'Port', 'Service', 'State']].to_string(index=False))

    print("-" * 60)
    
    # 意図的に埋め込んだ異常が検出できているか確認するためのヒント
    print("\n[解説]")
    print("通常のネットワークでは、Webサーバー(80/http)などは多数存在するため頻度が高くなります。")
    print("一方、'80/mysql' や '65123/unusual-svc' は稀にしか出現しないため、")
    print("この頻度分析アルゴリズムによって「異常」として浮かび上がります。")

# 実行
if __name__ == "__main__":
    # Pandasがインストールされている必要があります (pip install pandas)
    analyze_nmap_xml()