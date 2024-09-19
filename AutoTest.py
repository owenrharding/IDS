import sys
from os import walk

rules = sys.argv[1]
outputs = sys.argv[2]
pcaps = sys.argv[3]
files = []
data = []
rulespath = sys.argv[1]
outputpath = sys.argv[2]
pcappath = sys.argv[3]
for (trash, alsotrash, filenames) in walk(rules):
    files.extend(filenames)

for (trash, alsotrash, filenames) in walk(rules):
    data.extend(filenames)

sys.argv = sys.argv[:-1]
for file in files:
    script = open("IDS.py", 'r')
    pcap = file
    pcap = pcap.replace('.txt', '')
    if pcap in ['task1', 'task2', 'task3', 'task4', 'task5', 'task6', 'task7']:
        pcap = "task1-7.pcap"
    elif pcap == "task8":
        pcap = "task8.pcap"
    elif pcap in ['task9', 'task10', 'task11']:
        pcap = "task9-11.pcap"
    else:
        pcap += (".pcap")
    sys.argv[1] = f"{pcappath}/{pcap}"
    sys.argv[2] = f"{rulespath}/{file}"
    exec(script.read())

    #compare ids log and expected output file
    output = file.replace('.txt', 'out.txt')
    output = open(f"{outputpath}/{output}", 'r')
    outputlines = output.readlines()
    log = open("IDS_log.txt", 'r')
    loglines = log.readlines()
    if len(outputlines) != len(loglines):
        print(f"Error in {file}: Mismatching line numbers")
    for i in range(len(loglines)):
        if loglines[i][19:] != outputlines[i][19:]:
            print(f"Error in {file}: Mismatching line {str(i)} ({loglines[i][19:]} | expected | {outputlines[i][19:]}")

    output.close()
    log.close()
    script.close()
