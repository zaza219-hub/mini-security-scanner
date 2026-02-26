#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import requests
import urllib.parse
import concurrent.futures
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

from payloads import Payloads
from report import Report
from utils import Utils

init(autoreset=True)

VERSION = "1.0.0"
TIMEOUT = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
MAX_THREADS = 5

class Scanner:
    def __init__(self, targets, verbose=False, output=None, threads=MAX_THREADS, proxy=None, delay=0):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.verbose = verbose
        self.output = output
        self.threads = threads
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': USER_AGENT})
        
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        
        self.results = {
            'scan_start': Utils.get_timestamp(),
            'targets': self.targets,
            'forms': [],
            'vulnerabilities': []
        }
        self.discovered_urls = set()
        
    def log(self, message, level='info'):
        if self.verbose:
            print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")
        Utils.log(message, level)
    
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_banner(self):
        banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════╗
{Fore.RED}║  {Fore.WHITE}███╗   ███╗██╗███╗   ██╗██╗     ███████╗███████╗{Fore.RED}  ║
{Fore.RED}║  {Fore.WHITE}████╗ ████║██║████╗  ██║██║     ██╔════╝██╔════╝{Fore.RED}  ║
{Fore.RED}║  {Fore.WHITE}██╔████╔██║██║██╔██╗ ██║██║     █████╗  ███████╗{Fore.RED}  ║
{Fore.RED}║  {Fore.WHITE}██║╚██╔╝██║██║██║╚██╗██║██║     ██╔══╝  ╚════██║{Fore.RED}  ║
{Fore.RED}║  {Fore.WHITE}██║ ╚═╝ ██║██║██║ ╚████║███████╗███████╗███████║{Fore.RED}  ║
{Fore.RED}║  {Fore.WHITE}╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝{Fore.RED}  ║
{Fore.RED}║                                                              ║
{Fore.RED}║  {Fore.GREEN}Web Security Scanner v{VERSION}{Fore.RED}                                      ║
{Fore.RED}║  {Fore.YELLOW}Termux & Windows Uyumlu{Fore.RED}                                         ║
{Fore.RED}╚══════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def print_menu(self):
        print(f"\n{Fore.CYAN}╔════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║         ANA MENÜ                  ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╠════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}[1] {Fore.GREEN}Tek URL Tara{Fore.CYAN}                    ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}[2] {Fore.GREEN}URL Listesi Tara{Fore.CYAN}                 ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}[3] {Fore.GREEN}Ayarlar{Fore.CYAN}                          ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║ {Fore.WHITE}[4] {Fore.GREEN}Çıkış{Fore.CYAN}                            ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚════════════════════════════════════╝{Style.RESET_ALL}")
    
    def print_settings(self, threads, delay, proxy):
        print(f"\n{Fore.YELLOW}╔════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║         AYARLAR                   ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}╠════════════════════════════════════╣{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║ {Fore.WHITE}[1] Thread Sayısı: {Fore.GREEN}{threads}{Fore.YELLOW}               ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║ {Fore.WHITE}[2] Delay: {Fore.GREEN}{delay}s{Fore.YELLOW}                         ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║ {Fore.WHITE}[3] Proxy: {Fore.GREEN}{proxy or 'Yok'}{Fore.YELLOW}              ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}║ {Fore.WHITE}[4] Ana Menü{Fore.YELLOW}                        ║{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}╚════════════════════════════════════╝{Style.RESET_ALL}")
    
    def crawl_target(self, target):
        try:
            self.log(f"Taranıyor: {target}")
            r = self.session.get(target, timeout=TIMEOUT)
            soup = BeautifulSoup(r.text, 'html.parser')
            
            forms = []
            for form in soup.find_all('form'):
                f = {
                    'target': target,
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name', '')
                    if name:
                        f['inputs'].append({
                            'name': name,
                            'type': inp.get('type', 'text')
                        })
                
                forms.append(f)
                self.results['forms'].append(f)
            
            self.log(f"{len(forms)} form bulundu")
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('/') or href.startswith(target):
                    full = urljoin(target, href)
                    parsed = urlparse(full)
                    if parsed.scheme in ['http', 'https']:
                        self.discovered_urls.add(full)
                        
        except Exception as e:
            self.log(f"Hata: {str(e)}", 'error')
    
    def test_url(self, url):
        try:
            parsed = urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            if not params:
                return
            
            for param in params:
                for payload, desc in Payloads.SQL:
                    if self.delay:
                        time.sleep(self.delay)
                    self.test_sql(url, param, payload, desc)
                
                for payload, desc in Payloads.XSS:
                    if self.delay:
                        time.sleep(self.delay)
                    self.test_xss(url, param, payload, desc)
                
                for payload, desc in Payloads.COMMAND:
                    if self.delay:
                        time.sleep(self.delay)
                    self.test_command(url, param, payload, desc)
                    
        except Exception as e:
            self.log(f"URL test hatası: {str(e)}", 'error')
    
    def test_sql(self, url, param, payload, desc):
        try:
            test_url = url.replace(f"={param}", f"={urllib.parse.quote(payload)}")
            r = self.session.get(test_url, timeout=TIMEOUT)
            
            errors = [
                "sql", "mysql", "syntax error", "unclosed quotation",
                "you have an error", "warning: mysql", "odbc", "driver",
                "ora-", "postgresql", "sqlite"
            ]
            
            for e in errors:
                if e.lower() in r.text.lower():
                    self.results['vulnerabilities'].append({
                        'type': 'SQL Injection',
                        'target': url,
                        'param': param,
                        'payload': payload,
                        'description': desc,
                        'evidence': e
                    })
                    self.log(f"{Fore.RED}[!] SQLi: {param} @ {url}{Style.RESET_ALL}")
                    return True
        except:
            pass
        return False
    
    def test_xss(self, url, param, payload, desc):
        try:
            test_url = url.replace(f"={param}", f"={urllib.parse.quote(payload)}")
            r = self.session.get(test_url, timeout=TIMEOUT)
            
            if payload in r.text:
                self.results['vulnerabilities'].append({
                    'type': 'XSS',
                    'target': url,
                    'param': param,
                    'payload': payload,
                    'description': desc,
                    'evidence': 'Payload response içinde'
                })
                self.log(f"{Fore.RED}[!] XSS: {param} @ {url}{Style.RESET_ALL}")
                return True
        except:
            pass
        return False
    
    def test_command(self, url, param, payload, desc):
        try:
            test_url = url.replace(f"={param}", f"={urllib.parse.quote(payload)}")
            r = self.session.get(test_url, timeout=TIMEOUT)
            
            indicators = ["root:", "bin/", "etc/", "uid=", "gid=", "groups="]
            
            for i in indicators:
                if i in r.text:
                    self.results['vulnerabilities'].append({
                        'type': 'Command Injection',
                        'target': url,
                        'param': param,
                        'payload': payload,
                        'description': desc,
                        'evidence': i
                    })
                    self.log(f"{Fore.RED}[!] Command Inj: {param} @ {url}{Style.RESET_ALL}")
                    return True
        except:
            pass
        return False
    
    def test_form(self, form):
        try:
            target = form['target']
            action = form['action']
            method = form['method']
            full_url = urljoin(target, action)
            
            for inp in form['inputs']:
                param = inp['name']
                
                if method == 'GET':
                    for payload, desc in Payloads.SQL:
                        test = f"{full_url}?{param}={urllib.parse.quote(payload)}"
                        self.test_sql(test, param, payload, desc)
                    
                    for payload, desc in Payloads.XSS:
                        test = f"{full_url}?{param}={urllib.parse.quote(payload)}"
                        self.test_xss(test, param, payload, desc)
                        
        except Exception as e:
            self.log(f"Form test hatası: {str(e)}", 'error')
    
    def run_scan(self, targets):
        self.clear_screen()
        self.print_banner()
        print(f"\n{Fore.YELLOW}[+] Tarama başlatılıyor...{Style.RESET_ALL}")
        
        start = time.time()
        
        for target in targets:
            self.crawl_target(target)
        
        self.log(f"{len(self.discovered_urls)} URL taranıyor...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(self.test_url, self.discovered_urls)
        
        self.log(f"{len(self.results['forms'])} form taranıyor...")
        
        for form in self.results['forms']:
            self.test_form(form)
        
        elapsed = time.time() - start
        self.results['scan_duration'] = f"{elapsed:.2f}s"
        self.results['scan_end'] = Utils.get_timestamp()
        
        print(f"\n{Fore.GREEN}[+] Tarama tamamlandı: {elapsed:.2f}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Toplam URL: {len(self.discovered_urls)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] Toplam Form: {len(self.results['forms'])}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] Zafiyet: {len(self.results['vulnerabilities'])}{Style.RESET_ALL}")
        
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}ZAFİYET LİSTESİ:{Style.RESET_ALL}")
            for v in self.results['vulnerabilities']:
                print(f"  {Fore.RED}[!] {v['type']} @ {v['target']} ({v['param']}){Style.RESET_ALL}")
        
        if self.output:
            Report.save(self.results, self.output)
            print(f"{Fore.GREEN}[+] Rapor kaydedildi: {self.output}{Style.RESET_ALL}")
        
        input(f"\n{Fore.YELLOW}[+] Devam etmek için Enter'a basın...{Style.RESET_ALL}")
    
    def interactive_mode(self):
        threads = MAX_THREADS
        delay = 0
        proxy = None
        
        while True:
            self.clear_screen()
            self.print_banner()
            self.print_menu()
            
            choice = input(f"\n{Fore.GREEN}[?] Seçiminiz: {Style.RESET_ALL}").strip()
            
            if choice == '1':
                self.clear_screen()
                self.print_banner()
                url = input(f"\n{Fore.GREEN}[?] Hedef URL: {Style.RESET_ALL}").strip()
                if url:
                    output = input(f"{Fore.GREEN}[?] Çıktı dosyası (boş geçebilirsiniz): {Style.RESET_ALL}").strip()
                    self.output = output if output else None
                    self.run_scan([url])
            
            elif choice == '2':
                self.clear_screen()
                self.print_banner()
                list_file = input(f"\n{Fore.GREEN}[?] URL listesi dosyası: {Style.RESET_ALL}").strip()
                if list_file and os.path.exists(list_file):
                    with open(list_file, 'r') as f:
                        targets = [line.strip() for line in f if line.strip()]
                    output = input(f"{Fore.GREEN}[?] Çıktı dosyası (boş geçebilirsiniz): {Style.RESET_ALL}").strip()
                    self.output = output if output else None
                    self.run_scan(targets)
                else:
                    print(f"{Fore.RED}[!] Dosya bulunamadı!{Style.RESET_ALL}")
                    time.sleep(2)
            
            elif choice == '3':
                while True:
                    self.clear_screen()
                    self.print_banner()
                    self.print_settings(threads, delay, proxy)
                    
                    setting = input(f"\n{Fore.GREEN}[?] Seçiminiz: {Style.RESET_ALL}").strip()
                    
                    if setting == '1':
                        try:
                            new_threads = int(input(f"{Fore.GREEN}[?] Thread sayısı (1-20): {Style.RESET_ALL}").strip())
                            if 1 <= new_threads <= 20:
                                threads = new_threads
                                self.threads = threads
                        except:
                            pass
                    
                    elif setting == '2':
                        try:
                            new_delay = float(input(f"{Fore.GREEN}[?] Delay (saniye): {Style.RESET_ALL}").strip())
                            if new_delay >= 0:
                                delay = new_delay
                                self.delay = delay
                        except:
                            pass
                    
                    elif setting == '3':
                        new_proxy = input(f"{Fore.GREEN}[?] Proxy (örn: http://127.0.0.1:8080): {Style.RESET_ALL}").strip()
                        proxy = new_proxy if new_proxy else None
                        self.session.proxies.update({'http': proxy, 'https': proxy}) if proxy else None
                    
                    elif setting == '4':
                        break
                    
                    else:
                        print(f"{Fore.RED}[!] Geçersiz seçim!{Style.RESET_ALL}")
                        time.sleep(1)
            
            elif choice == '4':
                print(f"\n{Fore.YELLOW}[+] Çıkılıyor...{Style.RESET_ALL}")
                sys.exit(0)
            
            else:
                print(f"{Fore.RED}[!] Geçersiz seçim!{Style.RESET_ALL}")
                time.sleep(1)

def main():
    parser = argparse.ArgumentParser(description='WebSecScanner - Web Güvenlik Tarama Aracı')
    parser.add_argument('-u', '--url', help='Hedef URL')
    parser.add_argument('-l', '--list', help='URL listesi dosyası')
    parser.add_argument('-v', '--verbose', action='store_true', help='Detaylı çıktı')
    parser.add_argument('-o', '--output', help='Çıktı dosyası (json/csv/html/txt)')
    parser.add_argument('-t', '--threads', type=int, default=MAX_THREADS, help='Thread sayısı')
    parser.add_argument('--proxy', help='Proxy (ör: http://127.0.0.1:8080)')
    parser.add_argument('--delay', type=float, default=0, help='İstekler arası bekleme (saniye)')
    parser.add_argument('--interactive', action='store_true', help='İnteraktif mod')
    
    args = parser.parse_args()
    
    if args.interactive or len(sys.argv) == 1:
        s = Scanner([], args.verbose, args.output, args.threads, args.proxy, args.delay)
        s.interactive_mode()
        return
    
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except:
            print(f"{Fore.RED}[!] Liste dosyası okunamadı{Style.RESET_ALL}")
            return
    
    if not targets:
        print(f"{Fore.RED}[!] Hedef belirtilmedi{Style.RESET_ALL}")
        parser.print_help()
        return
    
    s = Scanner(targets, args.verbose, args.output, args.threads, args.proxy, args.delay)
    s.run_scan(targets)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Durduruldu{Style.RESET_ALL}")
        sys.exit(0)