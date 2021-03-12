import sys

file = open(sys.argv[1], 'r').readlines()
for line in file:
    if ".js" in line and ".json" not in line:
        if "min.js" not in line:
            if "jquery" not in line:
                temp = ".js"
                temp1 = line.strip()[:line.index(temp)+len(temp)]
                with open(sys.argv[2], "a") as fp:
                    temp1=temp1.replace("https://","")
                    temp2=temp1.replace("http://","")
                    fp.write(temp2+'\n')
