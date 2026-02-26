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
        print(f"\n[+] JSON rapor kaydedildi: {filename}")
    
    @staticmethod
    def save_csv(results, filename):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Tip', 'Hedef', 'Parametre', 'Payload', 'Açıklama'])
            for v in results['vulnerabilities']:
                w.writerow([
                    v['type'],
                    v['target'],
                    v['param'],
                    v['payload'],
                    v['description']
                ])
        print(f"\n[+] CSV rapor kaydedildi: {filename}")
    
    @staticmethod
    def save_html(results, filename):
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>WebSecScanner Raporu</title>
            <style>
                body {{ font-family: Arial; margin: 20px; background: #f5f5f5; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }}
                .stat-card {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
                .vuln {{ background: white; margin: 10px 0; padding: 10px; border-left: 5px solid #dc3545; border-radius: 5px; }}
                .critical {{ border-left-color: #dc3545; }}
                .high {{ border-left-color: #fd7e14; }}
                .medium {{ border-left-color: #ffc107; }}
                .low {{ border-left-color: #28a745; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>WebSecScanner Güvenlik Raporu</h1>
                <p>Tarama Başlangıç: {results['scan_start']}</p>
                <p>Tarama Bitiş: {results['scan_end']}</p>
                <p>Süre: {results.get('scan_duration', 'N/A')}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>Hedef Sayısı</h3>
                    <h2>{len(results['targets'])}</h2>
                </div>
                <div class="stat-card">
                    <h3>Bulunan URL</h3>
                    <h2>{len(results.get('discovered_urls', []))}</h2>
                </div>
                <div class="stat-card">
                    <h3>Bulunan Form</h3>
                    <h2>{len(results['forms'])}</h2>
                </div>
                <div class="stat-card">
                    <h3>Toplam Zafiyet</h3>
                    <h2>{len(results['vulnerabilities'])}</h2>
                </div>
            </div>
            
            <h2>Zafiyetler</h2>
        """
        
        for v in results['vulnerabilities']:
            html += f"""
            <div class="vuln critical">
                <h3>{v['type']}</h3>
                <p><strong>Hedef:</strong> {v['target']}</p>
                <p><strong>Parametre:</strong> {v['param']}</p>
                <p><strong>Payload:</strong> <code>{v['payload']}</code></p>
                <p><strong>Açıklama:</strong> {v.get('description', '')}</p>
                <p><strong>Kanıt:</strong> {v.get('evidence', '')}</p>
            </div>
            """
        
        html += f"""
            <h2>Formlar</h2>
            <table border="1" cellpadding="8">
                <tr><th>Hedef</th><th>Action</th><th>Method</th><th>Inputlar</th></tr>
        """
        
        for f in results['forms']:
            inputs = ', '.join([i['name'] for i in f['inputs']])
            html += f"<tr><td>{f['target']}</td><td>{f['action']}</td><td>{f['method']}</td><td>{inputs}</td></tr>"
        
        html += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        print(f"\n[+] HTML rapor kaydedildi: {filename}")
    
    @staticmethod
    def save_txt(results, filename):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("=" * 60 + "\n")
            f.write("WEBSECSCANNER GÜVENLİK RAPORU\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"Tarama Başlangıç: {results['scan_start']}\n")
            f.write(f"Tarama Bitiş: {results['scan_end']}\n")
            f.write(f"Hedefler: {', '.join(results['targets'])}\n\n")
            
            f.write("-" * 60 + "\n")
            f.write(f"ZAFİYETLER ({len(results['vulnerabilities'])})\n")
            f.write("-" * 60 + "\n\n")
            
            for i, v in enumerate(results['vulnerabilities'], 1):
                f.write(f"{i}. {v['type']}\n")
                f.write(f"   Hedef: {v['target']}\n")
                f.write(f"   Parametre: {v['param']}\n")
                f.write(f"   Payload: {v['payload']}\n")
                f.write(f"   Açıklama: {v.get('description', '')}\n")
                f.write(f"   Kanıt: {v.get('evidence', '')}\n\n")
            
            f.write("-" * 60 + "\n")
            f.write(f"FORMLAR ({len(results['forms'])})\n")
            f.write("-" * 60 + "\n\n")
            
            for frm in results['forms']:
                f.write(f"Hedef: {frm['target']}\n")
                f.write(f"Action: {frm['action']}\n")
                f.write(f"Method: {frm['method']}\n")
                f.write(f"Inputlar: {', '.join([i['name'] for i in frm['inputs']])}\n\n")
        
        print(f"\n[+] TXT rapor kaydedildi: {filename}")