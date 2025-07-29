import logging
import sys

def setup_logging():
    # Kök logger'ı yapılandır
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO) # Varsayılan log seviyesi

    # StreamHandler (konsola çıktı için)
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    # FileHandler (dosyaya çıktı için - opsiyonel)
    # log_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app.log")
    # file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
    # file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    # file_handler.setFormatter(file_formatter)
    # root_logger.addHandler(file_handler)

def get_logger(name):
    return logging.getLogger(name)

if __name__ == '__main__':
    setup_logging()
    test_logger = get_logger("TestLogger")
    test_logger.info("Bu bir bilgi mesajı.")
    test_logger.warning("Bu bir uyarı mesajı.")
    test_logger.error("Bu bir hata mesajı.")