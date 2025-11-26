import time
import random

def now():
    return int(time.time())

def rand_id(prefix="evt"):
    return prefix + "_" + str(random.randint(100000, 999999))