import re
import stix2
import traceback
import string
import datetime
import json
import argparse
import sys
import os
import traceback
import csv
args = sys.argv
args.pop(0)
arg_parser = argparse.ArgumentParser("Help")
arg_parser.add_argument("file_type", type=str, help="file or folder", default=1)
arg_parser.add_argument("file_name", type=str, help="file_name", default=2)
file_type = sys.argv[0]
file_name = sys.argv[1]
#print(file_type)
#print(file_name)
def csvtostix(file_type,file_name):
    count = 0
    data = {}
    labels = ""
    maldesc = ''
    malname = ''
    tot_file_path = ''
    url = []
    domain = []
    filename = []
    ip = []
    md5 = []
    registry = []
    email = []
    indlist =[]
    rellist = []
    sha1 = []
    sha256 = []
    m = datetime.datetime.now()
    c = m.strftime("%Y-%m-%d %H:%M:%S.{}".format(str(m).split('.')[1][:3]) + "Z")
    m = m.strftime("%Y-%m-%d %H:%M:%S.{}".format(str(m).split('.')[1][:3]) + "Z")
    malware = stix2.Malware(
                    created=c,
                    modified=m,
                    name=malname,
                    labels=labels,
                    description=maldesc
                    )
    try:
        each_data = []
        if file_type == "-f":
            each_data = []
            with open(file_name,"r") as f:
                csv_reader = csv.reader(f, delimiter=',')
                fields = csv_reader.next()
                tab = -1 
                for i in fields:
                    #print(i)
                    samp = []
                    tab+=1
                    with open(file_name,"r") as f:
                        csv_reader = csv.reader(f, delimiter=',')
                        for lines in csv_reader:
                            if lines[tab].strip():
                                if lines[tab] not in fields:
                                    samp.append(lines[tab].strip())
                    data[i] = samp
                    #print(data)
        elif file_type == "-F":
            each_data = []
            indiv_data = []
            if os.path.exists(file_name):
                for eachfile in os.walk(file_name):
                    for each_file in eachfile[2]:
                        with open(file_name+'/'+each_file,"r") as f:
                            csv_reader = csv.reader(f, delimiter=',')
                            fields = csv_reader.next()
                            tab = -1 
                            for i in fields:
                                samp1 = []
                                tab+=1
                                with open(file_name,"r") as f:
                                    csv_reader = csv.reader(f, delimiter=',')
                                    for lines in csv_reader:
                                        if lines[tab].strip():
                                            if lines[tab] not in fields:
                                                samp1.append(lines[tab].strip())
                                data[i].extend(samp1)    
                
            else:
                print("please enter a valid folder containing json files with valid folder path")
                print("Usage : python csvtostix.py <-f>/<-F> file_name/folder_name")
                print(" Example : python csvtostix.py -f APT34.csv")
                print(" Example : python csvtostix.py -F /home/user/Desktop/IOC_files/" )
                print("Submit the folder, which does not contain any subfolders")
                sys.exit()
            
        else: 
            print("Please enter the command as -f (for file) or -F (for folder) followed by File name or Folder name  with sapce")
            print("Usage : python csvtostix.py <-f>/<-F> file_name/folder_name")
            print(" Example : python csvtostix.py -f APT34.csv")
            print(" Example : python csvtostix.py -F /home/user/Desktop/IOC_files/" )
            sys.exit()
            
        #print(data) 
        if data:
            domain = data.get("Domain","")
            filepath1 = data.get("FilePath","")
            sha1 = data.get("SHA1","")
            registry = data.get("RegistryPath","")
            filename = data.get("FileName","")
            url = data.get("URL","")
            ip = data.get("IPAddress","")
            filename1 = data.get("FileName","")
            #filename = filename1 + filepath1
            filename = filename1
            sha256 = data.get("SHA256","")
            #domain = data32["Emails"]
            md5 = data.get("MD5","")
            #print(filename)
          
            for each_ip in ip:
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='IP',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[ipv4-addr:value = '" + each_ip.strip() + "']",
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_url in url:
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='url',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[url:value = 'http://" +each_url.split('//')[-1].split('/')[0].strip("'") + "'" + "]",
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_domain in domain:
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='domain-name',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[domain-name:value = '"+each_domain.split('//')[-1].split('/')[0].strip("'")+"']", 
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_filename in filename:
                tot_file_path = ''
                exact_name = each_filename.split('\\')
                split_path_name = each_filename.split('\\')[0:-1]
                if split_path_name:
                    for path in split_path_name:
                        tot_file_path = tot_file_path+ '\\\\'+ path
                if len(exact_name)>1:
                    indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='file',
                                description=" ",
                                labels=["malicious-activity"],
                                #pattern="[file:name = '" + each_filename.split('\\')[-1].strip("'") + "']",
                                pattern="[file:name = '" + each_filename.split('\\')[-1].strip("'") + "' AND file:parent_directory_ref.path = '"+ tot_file_path +"']",
                                valid_from=c
                            )
                else:
                    indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='file',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[file:name = '" + each_filename.strip("'") + "']",
                                valid_from=c
                            )
                    
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_registry in registry:
                each_registry = each_registry.replace("\\","\\\\")
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='win-registry-key',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[windows-registry-key:key = '" + each_registry + "']",
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_md5 in md5:
                each_md5 = re.sub(r'[^A-Za-z0-9]+', '', each_md5) 
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='MD5',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[file:hashes.md5 = '" + each_md5i.strip() + "']",
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_sha1 in sha1:
                each_sha1 = re.sub(r'[^A-Za-z0-9]+', '', each_sha1) 
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='MD5',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[file:hashes.'SHA-1' = '" + each_sha1.strip() + "']",
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            for each_sha256 in sha256:
                each_sha256 = re.sub(r'[^A-Za-z0-9]+', '', each_sha256) 
                indicator = stix2.Indicator(
                                created=c,
                                modified=m,
                                name='MD5',
                                description=" ",
                                labels=["malicious-activity"],
                                pattern="[file:hashes.'SHA-256' = '" + each_sha256.strip() + "']",
                                valid_from=c
                            )
                if indicator not in indlist:
                    indlist.append(indicator)
            print(len(indlist))
            obj_range = int((len(indlist)/50))+1
    
            ind1 = 0
            ind2 = 50
            #print(obj_range)
            for num in range(obj_range):
                new_list = []
                #print(str(ind1)+"ind1")
                #print(str(ind2)+"ind2")
                if (ind2 - ind1) != 50:
                    new_list = indlist[ind1: ]
                    #print("if111111111111")
                else:
                    #print("%%")
                    #print(ind1)
                    #print(ind2)
                    #print("***")
    
                    new_list = indlist[ind1:ind2]
                for ind in new_list:
                    #print(ind)
                    count += 1
                    val = 'relationship' + str(count)
                    val = stix2.Relationship(ind, 'indicates', malware)
                    rellist.append(val)
                    IOC = stix2.Bundle(objects=[malware] + rellist + new_list)
                    if IOC:
                        #print(type(num))
                        
                        num = str(num)
                        if sys.argv[1].split("/")[-1]:
                            with open(sys.argv[1].split("/")[-1].split(".")[0]+'_'+str(int(num)+1)+'.ioc', 'w') as fp:
                                fp.write(json.dumps(json.loads(str(IOC)), indent=2))
                        elif sys.argv[1].split("/")[-2]:
                           with open(sys.argv[1].split("/")[-2].split(".")[0]+'_'+str(int(num)+1)+'+.ioc', 'w') as fp:
                                fp.write(json.dumps(json.loads(str(IOC)), indent=2))
                        else:
                           with open(sys.argv[1].split("/")[0].split(".")[0]+'_'+str(int(num)+1)+'+.ioc', 'w') as fp:
                                fp.write(json.dumps(json.loads(str(IOC)), indent=2))
                    else:
                        pass
                ind1 = ind1+50
                ind2 = ind2+50
                rellist = []
        else:
            print("please enter a valid file/folder containing json files containing indicator data")
            print("Usage : python csvtostix.py <-f>/<-F> file_name/folder_name")
            print(" Example : python csvtostix.py -f APT34.csv")
            print(" Example : python csvtostix.py -F /home/user/Desktop/IOC_files/" )
    except IOError as err:
        print("please enter a valid folder containing csv files with valid folder path")
        print("Usage : python csvtostix.py <-f>/<-F> file_name/folder_name")
        print(" Example : python csvtostix.py -f APT34.csv")
        print(" Example : python csvtostix.py -F /home/user/Desktop/IOC_files/" )
        print("Submit the folder, which does not contain any subfolders")
    except Exception as e:
        print(traceback.format_exc())
        print(e)
    return
csvtostix(file_type,file_name)
