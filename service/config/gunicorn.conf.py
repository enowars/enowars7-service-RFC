import multiprocessing

workers = min(4, multiprocessing.cpu_count())
bind = "127.0.0.1:5005"
