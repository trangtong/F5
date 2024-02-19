#!/usr/bin/python3

import subprocess as p
import os
import string
import json
import dateutil.parser as dateparser

from itertools import groupby
from operator import itemgetter
from utils import utils as u
from utils import color as color
from f5.bigip import ManagementRoot
from datetime import date



class F5():
    def __init__(self, f5_ip: string, usrname: string, passwd: string):
        try:
            self.mgmt = ManagementRoot(f5_ip, usrname, passwd)
        except Exception as e:
            print("{}".format(e))
        except:
            print("Failed to init connection to F5!")

    def list(self, type: string, detail: bool = False):
        """
        Params:
        - type: cert, key, client_profile, vip
        - detail:
          - True: show full information
          - False: show name only
        """
        data = None
        if (type == "cert"):
            data = self.mgmt.tm.sys.crypto.certs.get_collection()
        elif (type == "key"):
            data = self.mgmt.tm.sys.file.ssl_keys.get_collection()
        elif (type == "client_profile"):
            data = self.mgmt.tm.ltm.profile.client_ssls.get_collection()
        elif (type == "vip"):
            data = self.mgmt.tm.ltm.virtuals.get_collection()
        else:
            raise ValueError(
                "Type {} not exists! [cert, key, client_profile, vip] only!".format(type))

        if (detail):
            for el in data:
                print('\n\t\t\t\t\t\t\t--- {}'.format(el.raw['name']))
                for d in el.__dict__:
                    print(' {}: {}'.format(d, el.raw[d]))
        else:
            for el in data:
                print('---  {}'.format(el.raw['name']))

        return 0

    def get_vips_sslProfile(self, detail: bool = False):
        """
        Get VIPs information

        Params:
        - detail:
          - True: get all information
          - False: ["name", "IP", "cert", "key"] only

        Return:
        - Raw ssl profile
        - [{'name': 'test-vip', 'IP': '/Common/0.0.0.0:0',
            'cert': '/Common/cert.pem', 'key': '/Common/privkey.pem'}]
        """
        res = []
        try:
            virtuals = self.mgmt.tm.ltm.virtuals.get_collection()
        except Exception as e:
            print("{} {}".format(
                'Failed to get vips collection. Reasons are below!\n', e))
            return 1
        except:
            print("{}".format("Unknown Error. Failed to get vips collection!"))
            return 1

        for virtual in virtuals:
            try:
                for profile in virtual.profiles_s.get_collection():
                    if profile.context == "clientside" and profile != None and profile.name != "tcp" and profile.name != "clientssl":
                        try:
                            pobj = self.mgmt.tm.ltm.profile.client_ssls.client_ssl.load(
                                name=profile.name)
                        except Exception as e:
                            print("{} {}".format(
                                'Failed to load vip client ssl profile. Reasons are below!\n', e))
                            return 1
                        except:
                            print("{}".format(
                                "Unknown Error. Failed to load vip client ssl profile!"))
                            return 1

                        if (detail):
                            res.append([virtual.name, pobj.raw])
                        else:
                            res.append({"name": virtual.name, "IP": virtual.destination, "profile": profile.name,
                                        "cert": pobj.certKeyChain[0]["cert"], "key": pobj.certKeyChain[0]["key"]})
            except Exception as e:
                print("{} {}".format(
                    'Failed to get collection of vip profiles. Reasons are below!\n', e))
                return 1
            except:
                print("{}".format(
                    "Unknown Error. Failed to get collection of vip profiles!"))
                return 1

        return res

    def get_certs_expired_date(self, list_cert_fullPath: list):
        """
        Get cert expiration date based on the given list

        Params:
        - list_cert_fullPath: List of full path cert. Ex: ["/Common/cert.pem",...]

        Return:
        - List of dict
        - Ex: [{'cert': '/Common/new-cert.pem', 'expired': 'Jan 12 07:07:24 2023 GMT'}]
        """
        res = []
        for cert in list_cert_fullPath:
            tmp = cert.split("/")
            if (len(tmp[0]) == len(cert)):
                raise ValueError("{}".format(
                    "Invalid input, element must contains full path of certificate!\n Ex: /Common/new-cert.pem"))

            try:
                cert_obj = self.mgmt.tm.sys.crypto.certs.cert.load(
                    name=tmp[2], partition=tmp[1])
            except:
                print("{}".format("Unknown Error. Failed to load certificate!"))
                return 1

            cert_raw = cert_obj.raw
            res.append(
                {"cert": cert, "expired": cert_raw['apiRawValues']['expiration']})

        return res

    def import_cert(self, crt_name: string, crt_file: string, key_file: string):
        """
        Import local cert and key file to F5

        Params:
        - crt_name: certificate name in F5. Ex: "cert-name"
        - crt_file: file name. Ex: "cert.pem" (current working dir) , "/path/to/cert.pem"
        - key_file: file name. Ex: "key.pem"
        """
        if (not os.path.isfile(crt_file)) or (not os.path.isfile(key_file)):
            raise ValueError("{} or {} not exists".format(crt_file, key_file))

        try:
            self.mgmt.shared.file_transfer.uploads.upload_file(
                filepathname=r'{}'.format(
                    crt_file),
                target=crt_file)
        except Exception as e:
            print(
                'import {} to F5 /var/config/rest/downloads/ failed, reason is '.format(crt_file) + str(e))
        except:
            print("error")
            return 1
        try:
            self.mgmt.shared.file_transfer.uploads.upload_file(
                filepathname=r'{}'.format(
                    key_file),
                target=key_file)
        except Exception as e:
            print(
                'import {} to F5 /var/config/rest/downloads/ failed, reason is '.format(key_file) + str(e))
        else:
            # create crt and key in GUI Web System  ››  Certificate Management : Traffic Certificate Management : SSL Certificate List
            crt_file = os.path.basename(crt_file)
            key_file = os.path.basename(key_file)

            if self.mgmt.tm.sys.file.ssl_certs.ssl_cert.exists(
                    name=crt_name,
                    partition='Common') is False:
                try:
                    self.mgmt.tm.sys.file.ssl_certs.ssl_cert.create(
                        name=crt_name,
                        partition='Common',
                        sourcePath='file:/var/config/rest/downloads/{}'.format(
                            crt_file))
                except Exception as e:
                    print('create crt in GUI Web System  ››  Certificate Management : '
                          'Traffic Certificate Management : SSL Certificate Listt {} failed!'
                          ' reason is: '.format(crt_file) + str(e))
                try:
                    self.mgmt.tm.sys.file.ssl_keys.ssl_key.create(
                        name=crt_name,
                        partition='Common',
                        sourcePath='file:/var/config/rest/downloads/{}'.format(
                            key_file))
                except Exception as e:
                    print('create key in GUI Web System  ››  Certificate Management {} failed! reason is:'
                          ' '.format(key_file) + str(e))

    def create_client_sslProfile(self, crt_name: string, profile_name: string):
        """
        Create new SSL Profile in F5
        Note: This function will only create profile at the /Common partition/path

        Params:
        - crt_name: name of the certificate in F5. Not the file name. Ex: "ca-bundle"
        - profile_name: name of the profile. Ex: "clientssl"
        """
        if (self.mgmt.tm.sys.file.ssl_certs.ssl_cert.exists(
                name=crt_name,
                partition='Common') is True):
            if (self.mgmt.tm.ltm.profile.client_ssls.client_ssl.exists(name=profile_name) is False):
                try:
                    self.mgmt.tm.ltm.profile.client_ssls.client_ssl.create(
                        name=profile_name, cert=crt_name, key=crt_name)
                except Exception as e:
                    print("{} {}".format(
                        'Failed to create ssl profile. Reasons are below!\n', e))
                    return 1
                except:
                    print("{}".format("Unknown Error. Failed to create ssl profile!"))
                    return 1
            else:
                raise ValueError("{} {} already exists".format(
                    "Failed to create client ssl profile.\n", profile_name))
        else:
            raise ValueError("{} {} not exists".format(
                "Failed to create client ssl profile.\n", crt_name))

    def update_client_sslProfile_cert(self, profile_name: string, crt_name: string):
        """
        Update Certificate on client SSL Profile in F5

        Params:
        - profile_name: SSL Profile name. Ex: "test-profile"
        - crt_name: Cert name. Ex: "test-cert"
        """
        if (self.mgmt.tm.sys.file.ssl_certs.ssl_cert.exists(
                name=crt_name,
                partition='Common') is True):
            if (self.mgmt.tm.ltm.profile.client_ssls.client_ssl.exists(name=profile_name) is True):
                try:
                    profile_obj = self.mgmt.tm.ltm.profile.client_ssls.client_ssl.load(
                        name=profile_name)
                    profile_obj.modify(chain=crt_name, cert=crt_name, key=crt_name)
                except Exception as e:
                    print("{} {}".format(
                        'Failed to modify ssl profile. Reasons are below!\n', e))
                    return 1
                except:
                    print("{}".format("Unknown Error. Failed to modify ssl profile!"))
                    return 1
            else:
                raise ValueError("{} Profile /Common/{} not exists".format(
                    "Failed to modify client ssl profile.\n", profile_name))
        else:
            raise ValueError("{} Cert /Common/{} not exists".format(
                "Failed to modify client ssl profile.\n", crt_name))

    def update_vip_client_sslProfile(self, vip_name: string, profile_name: string):
        """
        Update VIP client SSL Profile in F5

        Params:
        - vip_name: VIP name. Ex: "test-vip"
        - profile_name: SSL Profile name. Ex: "test-profile"
        """

        if (self.mgmt.tm.ltm.virtuals.virtual.exists(
                name=vip_name) is True):
            if (self.mgmt.tm.ltm.profile.client_ssls.client_ssl.exists(name=profile_name) is True):
                try:
                    try:
                        vip_obj = self.mgmt.tm.ltm.virtuals.virtual.load(
                            name=vip_name)
                        vip_obj.modify(profiles=profile_name)
                    except Exception as e:
                        print("{} {}".format(
                            'Failed to update vip client ssl profile. Reasons are below!\n', e))
                except:
                    print("{}".format(
                        "Unknown Error. Failed to update vip client ssl profile!"))
            else:
                raise ValueError("{} Profile /Common/{} not exists".format(
                    "Failed to modify client ssl profile.\n", profile_name))
        else:
            raise ValueError("{} VIP /Common/{} not exists".format(
                "Failed to modify client ssl profile.\n", vip_name))

webhook_url = '' # PRTG network-monitor

if __name__ == "__main__":
    usr = ""
    pss = ""
    f5 = F5("", usr, pss)

    tmp_vips = f5.get_vips_sslProfile()

    cert_list = []      # List of all certificate in F5
    vip_cert_name = []  # VIP name according to cert_list
    vips = []
    day_remain = 0
    vips = [i for i in tmp_vips if not (
        i['name'] == "" or i['name'] == "")]

    try:
        vips = sorted(vips, key=itemgetter('cert'))
        for key, value in groupby(vips, key=itemgetter('cert')):
            cert_list.append(key)
            tmp = []
            for i in list(value):
                tmp.append(i['name'])
            vip_cert_name.append(tmp)
    except:
        slack_mess = {"text": "Failed at split VIP(s) value"}
        u.slack_notification(webhook_url, slack_mess)
        exit()

    try:
        expired = f5.get_certs_expired_date(cert_list)     # Get expired date
    except:
        slack_mess = {"text": "Failed at get_certs_expired_date"}
        u.slack_notification(webhook_url, slack_mess)
        exit()

    with open('/usr/local/bin/data.json', 'r') as json_file:
        data = json.load(json_file)


        for i in range(len(expired)):       # Check cert expired or not and send slack noti
            cert = expired[i]['cert']
            cert_exp_date = expired[i]['expired']

            try:  
                if (u.compare_expired_date(cert_exp_date, 25) == False):
                    currentDate = date.today()
                    expired_date = dateparser.parse(cert_exp_date).date()
                    time_remain = expired_date - currentDate # Ex: '267 days, 0:00:00'
                    day_remain = int(str(time_remain).split("days")[0])

                    slack_mess = {
                        "text": "*[F5] Certificate Expiration Alert*",
                        "attachments": [{
                            "author_name": "Cert: {}".format(cert),
                            "color": color.COLOR_WARNING,
                            "text": "*Status*: Expired in *{}* (*{}* days remain) \n*Affected VIP(s)*: {}".format(cert_exp_date, day_remain, vip_cert_name[i]),
                        }]
                    }
                    u.slack_notification(webhook_url, slack_mess)


                    for d in data:
                        if (d['cert_name'] in cert) and (day_remain < 12) :
                            try:
                                local_cert_file =  d['cert_file']
                                local_key_file = d['key_file']
                                
                                sub = p.Popen("get_cert.sh {} {} {}".format(d['vault_url'], local_cert_file, local_key_file),
                                              stdout=p.PIPE, shell=True)
                                sub.wait()
        
                                new_cert = d['cert_name'] + "_" + \
                                    date.today().strftime("%b_%d")
                                sslProfile = d['profile_name']
                                f5.import_cert(new_cert, local_cert_file, local_key_file)
                                f5.update_client_sslProfile_cert(sslProfile, new_cert)
        
                                slack_mess = {
                                    "text": "{} is updated with /Common/{}".format(cert, new_cert)}
                                u.slack_notification(webhook_url, slack_mess)
        
                            except:
                                slack_mess = {
                                    "text": "Failed to updated {}".format(cert)}
                                u.slack_notification(webhook_url, slack_mess)

            except:
                slack_mess = {"text": "Failed at check {} expired".format(vip_cert_name[i])}
                u.slack_notification(webhook_url, slack_mess)
        json_file.close()
