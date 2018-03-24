import re 

with open("10000words.txt",'r') as f:
	contents = f.read()
	contents = re.sub(r'\b(\w)\b','',contents)

with open("10000words.txt",'w') as f:
	f.write(contents)

	