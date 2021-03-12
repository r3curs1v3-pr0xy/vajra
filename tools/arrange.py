import argparse


parser = argparse.ArgumentParser(description='Arrange Data in Proper Format')
parser.add_argument(
    '-f', '--file', help='file name t [ex : resolve.txt]', required=True)
args = parser.parse_args()

data = []

lines = open(args.file, 'r').readlines()

for line in lines:
    splits = line.strip().split("[")
    urls = (splits[0].replace('[', '')).replace(']', '')
    statuss = (splits[1].replace('[', '')).replace(']', '')
    titles = (splits[2].replace('[', '')).replace(']', '')
    ips = (splits[3].replace('[', '')).replace(']', '')
    data.append({"url": urls, "ip": ips, "title": titles.replace("'",""), "status": statuss})

with open(args.file+".json", "w") as fp:
    fp.write(str(data).replace("'", '"'))
    fp.close()
