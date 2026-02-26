#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
from datetime import datetime

LOG_FILE = "scanner.log"

# Log klasörünü kontrol et
log_dir = os.path.dirname(LOG_FILE)
if log_dir and not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

class Utils:
    @staticmethod
    def get_timestamp():
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def log(message, level='info'):
        if level == 'info':
            logging.info(message)
        elif level == 'error':
            logging.error(message)
        elif level == 'warning':
            logging.warning(message)
    
    @staticmethod
    def is_valid_url(url):
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    @staticmethod
    def read_urls_from_file(filename):
        urls = []
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and Utils.is_valid_url(line):
                        urls.append(line)
        except Exception as e:
            print(f"[!] Dosya okuma hatası: {e}")
        return urls
    
    @staticmethod
    def check_dependencies():
        try:
            import requests
            import bs4
            import colorama
            return True
        except ImportError as e:
            print(f"[!] Eksik kütüphane: {e}")
            return False