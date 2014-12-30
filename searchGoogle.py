from google import search
import time
lines=[]
with open('domains.txt') as f:
    lines = f.read().splitlines()
for line in lines:
	for url in search('site:'+line, stop=20):
		print(url)
	time.sleep(10)

