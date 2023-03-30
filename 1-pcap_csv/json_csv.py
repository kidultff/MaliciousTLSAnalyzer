import json
import time
import os
import csv
import math
import collections
from tld import get_fld
from pcap_mod import *
from time import sleep
import _thread
import numpy as np
import traceback

EXTENSIONTYPE_VALUES_REV = dict(map(reversed, EXTENSIONTYPE_VALUES.items()))

alexa = []
cctld_list = []


def load_alexa():
    global alexa
    with open('./alexa.txt', 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip('\n')
            alexa.append(line)
    with open('./whitelist.txt', 'r') as f:
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip('\n')
            alexa.append(line)
    return alexa


def load_cctld():
    global cctld_list
    with open('./cctld.txt', 'r', encoding='utf-8') as f:
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip('\n')
            line = line.split(' ')[0]
            cctld_list.append(line)
    return cctld_list


load_alexa()
load_cctld()


def get_entropy(inp_str):
    if inp_str == "":
        return 0, 0
    counter_char = collections.Counter(inp_str)
    entropy = 0
    for c, ctn in counter_char.items():
        _p = float(ctn) / len(inp_str)
        entropy += -1 * _p * math.log(_p, 2)
    return round(entropy, 7), (round(entropy, 7) / len(inp_str))


def get_template():
    data = {
        # meta info
        'src_ip': "", 'dst_ip': "", 'dst_port': "", 'server_name': "", "family": "",

        # based on TCP meta
        "is_fake_port": 0, "is_valid_port": 0, 'is_high_port': 0, 'from_high_port': 0,

        # based on time
        'duration': 0,
        'ipt_avg_dir_1': 0, 'ipt_avg_dir_2': 0, 'ipt_avg': 0,
        'ipt_std_dir_1': 0, 'ipt_std_dir_2': 0, 'ipt_std': 0,

        # based on bytes
        'bytes_out': 0, 'bytes_in': 0, 'entropy': 0,
        'payload_avg_dir_1': 0, 'payload_avg_dir_2': 0, 'payload_avg': 0,
        'payload_std_dir_1': 0, 'payload_std_dir_2': 0, 'payload_std': 0,

        # based on TLS Client Hello
        'client_ver': 0, 'server_ver': 0, "server_name_len": 0, 'client_key_len': 0, 'cs_cnt': 0,

        # based on TLS application data
        'pkts_out': 0, 'pkts_in': 0,
        "same_pkt_rate": 0, "pkt_0_19": 0, "pkt_20_39": 0, "pkt_40_79": 0,
        "pkt_80_159": 0, "pkt_160_319": 0, "pkt_320_639": 0, "pkt_640_1279": 0,
        "pkt_1280_2559": 0, "pkt_2560_5119": 0, "pkt_5120_inf": 0,

        # based on domain
        "server_name_entropy": 0, "server_name_entropy_avg": 0,
        'domain_idn': 0, 'domain_cctld': 0, 'domain_other': 0,

        # based on motivation
    }

    # pkt size
    for i in range(50):
        data['pkt_dir_' + str(i)] = 0
        data['pkt_len_' + str(i)] = 0
        data['pkt_time_' + str(i)] = 0

    # cs
    for cs in TLS_CIPHER_SUITE_REGISTRY.keys():
        data['cs_' + str(cs)] = 0

    # ext
    data['ce_cnt'] = 0
    for ext in EXTENSIONTYPE_VALUES:
        data['ce_' + str(ext)] = 0

    # sg
    data['sg_cnt'] = 0
    for item in TLS_SUPPORTED_GROUPS_REGISTRY:
        data['sg_' + str(item)] = 0

    # ec
    data['ec_cnt'] = 0
    for item in TLS_EC_POINT_FORMAT_REGISTRY:
        data['ec_' + str(item)] = 0

    # cert
    data['cert_cnt'] = 0
    data['c1_isu_len'] = 0
    data['c1_sk_len'] = 0
    data['c1_vld_t'] = 0
    data['s_name_eq_c1'] = 0
    data['c1_valid'] = 0
    data['c1_subj_len'] = 0
    data['c1_ext_len'] = 0
    data['c1_subj_pk_len'] = 0
    data['c1_domain_len'] = 0
    data['label'] = 1
    return data


def deal_single(json_data, cap_time, label, mal_family):
    # get time
    cap_time = time.mktime(time.strptime(cap_time + ' 00:00:00', "%Y-%m-%d %H:%M:%S"))
    data = get_template()
    tpl_len = len(data)

    # TCP metainfo
    data['src_ip'] = json_data['sa']
    data['dst_ip'] = json_data['da']
    data['dst_port'] = json_data['dp']
    data['family'] = mal_family
    data['entropy'] = json_data['entropy'] if 'entropy' in json_data else 0
    data['is_valid_port'] = int(json_data['dp'] in [443, 465, 993, 994, 995, 3389])
    data['is_fake_port'] = int(json_data['dp'] in [21, 22, 23, 53, 80])
    data['is_high_port'] = int(json_data['dp'] > 9999)
    data['from_high_port'] = int(json_data['sp'] >= 49152)
    data['label'] = label

    # TLS version
    try:
        data['client_ver'] = json_data['tls']['c_version']
    except:
        data['client_ver'] = -1
    try:
        data['server_ver'] = json_data['tls']['s_version']
    except:
        data['server_ver'] = -1

    # TLS server name
    server_name = json_data['tls']['sni'][0] if 'sni' in json_data['tls'].keys() \
                                                and len(json_data['tls']) > 0 else ''
    data['server_name'] = server_name
    data['server_name_len'] = len(server_name)
    data['server_name_entropy'], data['server_name_entropy_avg'] = get_entropy(server_name)
    try:
        data['domain_cctld'] = int(server_name[-3:] in cctld_list)
        data['domain_idn'] = int(server_name[-4:] in ['.com', '.net', '.org', '.edu', '.gov'])
        data['domain_other'] = int((not data['domain_idn']) and (not data['domain_cctld']))
    except:
        data['domain_other'] = 1
    try:
        if label and get_fld(server_name, fix_protocol=True) in alexa:
            return False
    except:
        label = label  # pass

    # client key
    try:
        data['client_key_len'] = int(len(json_data['tls']['c_key_exchange']) / 2)
    except:
        data['client_key_len'] = 0

    # client cipher suit
    if 'cs' in json_data['tls']:
        data['cs_cnt'] = len(json_data['tls']['cs'])

        for cs in json_data['tls']['cs']:
            cs = str(int(str(cs), 16))
            if 'cs_' + cs in data.keys():
                data['cs_' + cs] = 1
    else:
        data['cs_cnt'] = 0
        return False  # no cs -> ignore

    # client extension
    supports_groups = ""
    ec_point_formats = ""
    if 'c_extensions' in json_data['tls']:
        data['ce_cnt'] = len(json_data['tls']['c_extensions'])

        for ext in json_data['tls']['c_extensions']:
            for item in ext:
                if item in EXTENSIONTYPE_VALUES_REV.keys():
                    data['ce_' + str(EXTENSIONTYPE_VALUES_REV[item])] = 1
                    if item == 'supported_groups':
                        supports_groups = ext[item]
                    if item == 'ec_point_formats':
                        ec_point_formats = ext[item]

    # client support group
    data['sg_cnt'] = int(len(supports_groups) / 4)

    for item in range(data['sg_cnt']):
        sg = int(supports_groups[item * 4: item * 4 + 4], 16)
        if 'sg_' + str(sg) in data:
            data['sg_' + str(sg)] = 1

    # client  ec_point_formats
    data['ec_cnt'] = int(len(ec_point_formats) / 2)
    for item in range(data['ec_cnt']):
        ec = int(ec_point_formats[item * 2: item * 2 + 2], 16)
        if 'ec_' + str(ec) in data:
            data['ec_' + str(ec)] = 1

    # certificate
    if 's_cert' in json_data['tls']:
        data['cert_cnt'] = len(json_data['tls']['s_cert'])
        if data['cert_cnt'] >= 1:
            data['c1_sk_len'] = json_data['tls']['s_cert'][0]['signature_key_size'] \
                if 'signature_key_size' in json_data['tls']['s_cert'][0] else 0
            data['c1_isu_len'] = len(json_data['tls']['s_cert'][0]['issuer']) \
                if 'issuer' in json_data['tls']['s_cert'][0] else 0
            data['c1_subj_len'] = len(json_data['tls']['s_cert'][0]['subject']) \
                if 'subject' in json_data['tls']['s_cert'][0] else 0
            data['c1_ext_len'] = len(json_data['tls']['s_cert'][0]['extensions']) \
                if "extensions" in json_data['tls']['s_cert'][0] else 0
            data['c1_subj_pk_len'] = json_data['tls']['s_cert'][0]['subject_public_key_size'] \
                if 'subject_public_key_size' in json_data['tls']['s_cert'][0] else 0

            if 'validity_not_after' in json_data['tls']['s_cert'][0]:
                after = json_data['tls']['s_cert'][0]['validity_not_after'] \
                    if 'validity_not_after' in json_data['tls']['s_cert'][0] else 0
                before = json_data['tls']['s_cert'][0]['validity_not_before'] \
                    if 'validity_not_after' in json_data['tls']['s_cert'][0] else 0
                try:
                    after = time.mktime(time.strptime(after.replace(' GMT', ''), "%b %d %H:%M:%S %Y"))
                except:
                    after = 0
                try:
                    before = time.mktime(time.strptime(before.replace(' GMT', ''), "%b %d %H:%M:%S %Y"))
                except:
                    before = 0
                data['c1_vld_t'] = (after - before) / (60 * 60 * 24)
                data['c1_valid'] = int(after > cap_time > before)
            if "extensions" in json_data['tls']['s_cert'][0]:
                for ext in json_data['tls']['s_cert'][0]['extensions']:
                    for item in ext:
                        if "Subject Alternative Name" in item:
                            subj_domain = ext[item].replace('DNS:', '').replace(' ', '').split(',')
                            data['c1_domain_len'] = len(subj_domain)
                            for domain in subj_domain:
                                if domain.replace('*.', '') in server_name:
                                    data['s_name_eq_c1'] = 1
    else:
        data['cert_cnt'] = 0
        return False  # no cert -> ignore

    # per packet
    per_packet_len = []
    per_packet_len_dir_1 = []
    per_packet_len_dir_2 = []

    per_packet_ipt = []
    per_packet_ipt_dir_1 = []
    per_packet_ipt_dir_2 = []

    _pkt_cnt = 0

    for pkt in json_data['tls']['srlt']:
        if pkt['tp'] != 23:
            continue
        data['duration'] += pkt['ipt']

        direct = int(pkt['dir'] == '<') + 1

        data['pkt_dir_' + str(_pkt_cnt)] = direct
        data['pkt_len_' + str(_pkt_cnt)] = pkt['b']
        data['pkt_time_' + str(_pkt_cnt)] = pkt['ipt']

        if 1 == 1:
            if pkt['b'] < 20:
                data['pkt_0_19'] += 1
            elif pkt['b'] < 40:
                data['pkt_20_39'] += 1
            elif pkt['b'] < 80:
                data['pkt_40_79'] += 1
            elif pkt['b'] < 160:
                data['pkt_80_159'] += 1
            elif pkt['b'] < 320:
                data['pkt_160_319'] += 1
            elif pkt['b'] < 640:
                data['pkt_320_639'] += 1
            elif pkt['b'] < 1280:
                data['pkt_640_1279'] += 1
            elif pkt['b'] < 2560:
                data['pkt_1280_2559'] += 1
            elif pkt['b'] < 5120:
                data['pkt_2560_5119'] += 1
            else:
                data['pkt_5120_inf'] += 1

        if direct == 1:
            if pkt['ipt'] in per_packet_ipt_dir_1:
                data['same_pkt_rate'] += 1
            per_packet_len_dir_1.append(pkt['b'])
            per_packet_ipt_dir_1.append(pkt['ipt'])
        else:
            if pkt['ipt'] in per_packet_ipt_dir_2:
                data['same_pkt_rate'] += 1
            per_packet_len_dir_2.append(pkt['b'])
            per_packet_ipt_dir_2.append(pkt['ipt'])

        per_packet_len.append(pkt['b'])
        per_packet_ipt.append(pkt['ipt'])

        _pkt_cnt += 1
        if _pkt_cnt >= 50:
            break

    data['pkts_out'] = len(per_packet_ipt_dir_1)
    data['pkts_in'] = len(per_packet_ipt_dir_2)

    data['bytes_in'] = np.sum(per_packet_ipt_dir_1)
    data['bytes_out'] = np.sum(per_packet_ipt_dir_2)
    data['same_pkt_rate'] = (1.0 * data['same_pkt_rate'] / (data['pkts_out'] + data['pkts_in'])) \
        if (data['pkts_out'] + data['pkts_in']) != 0 else 0

    data['payload_avg_dir_1'] = np.mean(per_packet_len_dir_1) if len(per_packet_len_dir_1) != 0 else 0
    data['payload_avg_dir_2'] = np.mean(per_packet_len_dir_2) if len(per_packet_len_dir_1) != 0 else 0
    data['payload_avg'] = np.mean(per_packet_len) if len(per_packet_len_dir_1) != 0 else 0

    data['payload_std_dir_1'] = np.std(per_packet_len_dir_1) if len(per_packet_len_dir_1) != 0 else 0
    data['payload_std_dir_2'] = np.std(per_packet_len_dir_2) if len(per_packet_len_dir_2) != 0 else 0
    data['payload_std'] = np.std(per_packet_len) if len(per_packet_len) != 0 else 0

    data['ipt_avg_dir_1'] = np.mean(per_packet_ipt_dir_1) if len(per_packet_len_dir_1) != 0 else 0
    data['ipt_avg_dir_2'] = np.mean(per_packet_ipt_dir_2) if len(per_packet_len_dir_1) != 0 else 0
    data['ipt_avg'] = np.mean(per_packet_ipt) if len(per_packet_len_dir_1) != 0 else 0

    data['ipt_std_dir_1'] = np.std(per_packet_ipt_dir_1) if len(per_packet_ipt_dir_1) != 0 else 0
    data['ipt_std_dir_2'] = np.std(per_packet_ipt_dir_2) if len(per_packet_ipt_dir_2) != 0 else 0
    data['ipt_std'] = np.std(per_packet_ipt) if len(per_packet_ipt) != 0 else 0

    assert len(data) == tpl_len
    return data


good_cnt = 0
bad_cnt = 0
family = {}


def deal_file(root, file):
    global good_cnt, bad_cnt
    file_path = os.path.join(root, file)
    print(file_path)
    header = get_template().keys()

    family_labels = []
    if 'malware' in file:
        family_labels_arr = file.replace('malware_mta_', '')\
            .replace('malware_lastline_', '')\
            .replace('-', '_')\
            .split('_')

        family_labels = []
        for i in family_labels_arr:
            try:
                int(i)
            except:
                if '.json' not in i:
                    family_labels.append(i.lower())

        for label in family_labels:
           if label not in family:
            family[label] = 0

    with open(file_path, 'r') as f:
        _ = f.readline()
        while _:
            _ = f.readline()
            if _:
                json_data = json.loads(_)
                if 'tls' in json_data:
                    try:
                        mal_family = "|".join(family_labels)
                        c_data = deal_single(json_data, file[:10].replace('_', '-'), int('malware' in file), mal_family)
                        if not c_data:
                            continue
                        good_cnt += 1

                        for label in family_labels:
                            family[label] += 1

                        with open('../dataset/csvs/' + file.replace('json', 'csv'), 'a', newline='') as c:
                            f_csv = csv.writer(c)
                            if header:
                                f_csv.writerow(list(header))
                                header = False
                            f_csv.writerow(list(c_data.values()))
                    except Exception as e:
                        print(file_path)
                        traceback.print_exc()
                        print(json_data)
                        bad_cnt += 1


if __name__ == "__main__":
    rootdir = '../dataset/jsons'
    all_file = []
    for root, dirs, files in os.walk(rootdir):
        for file in files:
            all_file.append((root, file))


    def func():
        while True:
            if len(all_file):
                root, file = all_file.pop()
                deal_file(root, file)
            else:
                break


    _thread.start_new_thread(func, ())
    _thread.start_new_thread(func, ())
    _thread.start_new_thread(func, ())

    while True:
        sleep(10)
        print("\rremain: {} files, successful: {}, fail: {}".format(len(all_file), good_cnt, bad_cnt))
        print(family)
