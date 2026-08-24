import redis
import json

r = redis.Redis(host='127.0.0.1', port=6379, db=0, decode_responses=True)
length = r.llen("sis_queue")
print(f"Queue length: {length}")
if length > 0:
    for i in range(min(5, length)):
        item = r.lindex("sis_queue", i)
        print(f"Item {i}: {item[:200]}")
