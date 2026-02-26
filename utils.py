import logging
from datetime import datetime

LOG_FILE = "scanner.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
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
            with open(filename, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and Utils.is_valid_url(line):
                        urls.append(line)
        except:
            pass
        return urls