#!/usr/bin/python
import sys
import os
from subprocess import PIPE, Popen

ext = [".asp", ".aspx", ".cer", ".cfm", ".cfml", ".rb", ".php", ".php3", ".php4", ".php5", ".jsp", ".json", ".apk", ".ods", ".xls", ".xlsm", ".xlsx", ".bak", ".cab", ".cpl", ".dmp", ".drv", ".tmp", ".sys", ".doc", ".docx", ".pdf", ".txt", ".wpd", ".bat", ".bin", ".cgi", ".pl", ".py", ".exe", ".gadget", ".jar", ".msi", ".wsf", ".csv", ".dat", ".db", ".dbf",
       ".log", ".mdb", ".sav", ".sql", ".tar", ".xml", ".7z", ".arj", ".deb", ".pkg", ".rar", ".rpm", ".tar.gz", ".z", ".zip", ".bin", ".dmg", ".iso", ".toast", ".vcd", ".email", ".eml", ".emlx", ".msg", ".oft", ".ost", ".pst", ".vcf", ".shtm", ".shtml", ".phtm", ".phtml", ".jhtml", ".conf", ".yml", ".config", ".yaml", ".wsdl", ".java", ".key", ".html", ".sh"]
length = len(ext)


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True,
        universal_newlines=True
    )
    return process.communicate()[0]


try:
    args = sys.argv[1]
    outputfile = sys.argv[2]
    f = open(outputfile, "ab+")
    for i in range(0, length):
        payload = ext[i]
        a = "===="+payload+" ===="
        res = a.encode('utf-8')
        print("\n")
        command = "cat "+args+" |"
        command2 = ' \ '
        space = command2.replace(" ", "")
        final = command+" grep -i \'"+space+payload+space+">$\'"
        f.write(res)
        f.write("\n")
        f.write("\n")
        f.write(cmdline(final))
        f.write("\n")
    f.close()
except IndexError:
    print("./grapX url output_filename: Please Specify files!!")
