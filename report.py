#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import csv
import os
from datetime import datetime

class Report:
    @staticmethod
    def save(results, filename):
        if filename.endswith('.json'):
            Report.save_json(results, filename)
        elif filename.endswith('.csv'):
            Report.save_csv(results, filename)
        elif filename.endswith('.html'):
            Report.save_html(results, filename)
        elif filename.endswith('.txt'):
            Report.save_txt(results, filename)
        else:
            Report.save_json(results, filename + '.json')
    
    @staticmethod
    def save_json(results, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}[+] JSON rapor kaydedildi: {filename}{Style.RESET_ALL}")
    
    @staticmethod
    def save_csv(results, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Tip', 'Hedef', 'Parametre', 'Payload', 'Açıklama', 'Kanıt'])
            for v in results['vulnerabilities']:
                w.writerow([
                    v['type'],
                    v['target'],
                    v['param'],
                    v['payload'],
                    v['description'],
                    v.get('evidence', '')
                ])
        print(f"\n{Fore.GREEN}[+] CSV rapor kaydedildi: {filename}{Style.RESET_ALL}")
    
    @staticmethod
    def save_html(results, filename):
        vuln_count = len(results['vulnerabilities'])
        form_count = len(results['forms'])
        target_count = len(results['targets'])
        
        vuln_rows = ""
        for v in results['vulnerabilities']:
            vuln_rows += f"""
            <tr>
                <td><span class="vuln-badge">{v['type']}</span></td>
                <td>{v['target']}</td>
                <td><code>{v['param']}</code></td>
                <td><code>{v['payload'][:50]}</code></td>
                <td>{v.get('evidence', '')}</td>
            </tr>
            """
        
        form_rows = ""
        for f in results['forms']:
            inputs = ', '.join([i['name'] for i in f['inputs']])
            form_rows += f"""
            <tr>
                <td>{f['target']}</td>
                <td>{f['action']}</td>
                <td>{f['method']}</td>
                <td>{inputs}</td>
            </tr>
            """
        
        html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSecScanner Güvenlik Raporu</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }}
        .header h1 {{
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header p {{
            color: #666;
            font-size: 1.1em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        .stat-card h3 {{
            color: #666;
            font-size: 1em;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .vuln-critical {{
            border-left: 5px solid #dc3545;
        }}
        .vuln-high {{
            border-left: 5px solid #fd7e14;
        }}
        .vuln-medium {{
            border-left: 5px solid #ffc107;
        }}
        .section {{
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #333;
            margin-bottom: 20px;
            font-size: 1.8em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .vuln-badge {{
            background: #dc3545;
            color: white;
            padding: 5px 10px;
            border-radius: 5px;
            font-size: 0.9em;
            font-weight: 500;
        }}
        code {{
            background: #f8f9fa;
            padding: 3px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #dc3545;
        }}
        .footer {{
            text-align: center;
            color: white;
            margin-top: 30px;
            opacity: 0.8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 WebSecScanner Güvenlik Raporu</h1>
            <p>Tarama Başlangıç: {results['scan_start']}</p>
            <p>Tarama Bitiş: {results['scan_end']}</p>
            <p>Tarama Süresi: {results.get('scan_duration', 'N/A')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Hedef Sayısı</h3>
                <div class="stat-number">{target_count}</div>
            </div>
            <div class="stat-card">
                <h3>Bulunan Form</h3>
                <div class="stat-number">{form_count}</div>
            </div>
            <div class="stat-card">
                <h3>Toplam Zafiyet</h3>
                <div class="stat-number">{vuln_count}</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🚨 Tespit Edilen Zafiyetler</h2>
            <table>
                <thead>
                    <tr>
                        <th>Tip</th>
                        <th>Hedef</th>
                        <th>Parametre</th>
                        <th>Payload</th>
                        <th>Kanıt</th>
                    </tr>
                </thead>
                <tbody>
                    {vuln_rows}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📝 Tespit Edilen Formlar</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hedef</th>
                        <th>Action</th>
                        <th>Method</th>
                        <th>Inputlar</th>
                    </tr>
                </thead>
                <tbody>
                    {form_rows}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>WebSecScanner v1.0.0 - Güvenlik Tarama Aracı</p>
        </div>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"\n{Fore.GREEN}[+] HTML rapor kaydedildi: {filename}{Style.RESET_ALL}")
    
    @staticmethod
    def save_txt(results, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("WEBSECSCANNER GÜVENLİK RAPORU\n".center(80))
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Tarama Başlangıç: {results['scan_start']}\n")
            f.write(f"Tarama Bitiş: {results['scan_end']}\n")
            f.write(f"Süre: {results.get('scan_duration', 'N/A')}\n")
            f.write(f"Hedefler: {', '.join(results['targets'])}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write(f"ZAFİYETLER ({len(results['vulnerabilities'])})\n".center(80))
            f.write("-" * 80 + "\n\n")
            
            for i, v in enumerate(results['vulnerabilities'], 1):
                f.write(f"{i}. {v['type']}\n")
                f.write(f"   Hedef    : {v['target']}\n")
                f.write(f"   Parametre: {v['param']}\n")
                f.write(f"   Payload  : {v['payload']}\n")
                f.write(f"   Açıklama : {v.get('description', '')}\n")
                f.write(f"   Kanıt    : {v.get('evidence', '')}\n\n")
            
            f.write("-" * 80 + "\n")
            f.write(f"FORMLAR ({len(results['forms'])})\n".center(80))
            f.write("-" * 80 + "\n\n")
            
            for i, frm in enumerate(results['forms'], 1):
                f.write(f"{i}. Hedef : {frm['target']}\n")
                f.write(f"   Action : {frm['action']}\n")
                f.write(f"   Method : {frm['method']}\n")
                f.write(f"   Inputlar: {', '.join([i['name'] for i in frm['inputs']])}\n\n")
        
        print(f"\n{Fore.GREEN}[+] TXT rapor kaydedildi: {filename}{Style.RESET_ALL}")