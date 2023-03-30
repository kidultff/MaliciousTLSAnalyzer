import os

if __name__ == "__main__":
    rootdir = '/mnt/e/MaliciousTLSAnalyzer/dataset/pcaps'
    for root, dirs, files in os.walk(rootdir):
        for file in files:
            file_path = os.path.join(root, file)
            cmd = "~/joy/bin/joy ppi=1 bidir=1 tls=1 dns=1 http=1 entropy=1 \"{}\"  > " \
                  "\"/mnt/e/MaliciousTLSAnalyzer/dataset/jsons/{}.json\"" \
                .format(file_path, file.replace(".pcap", ''))
            print(cmd)
            os.system(cmd)
