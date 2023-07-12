import multiprocessing

workers = min(4, multiprocessing.cpu_count())
bind = "0.0.0.0:5005"
