#!/usr/bin/env python
import os
import sys
import syslog
import json
import ldb

from samba.auth import system_session
from samba.credentials import Credentials
from samba.param import LoadParm
from samba.samdb import SamDB
from samba.netcmd.user import GetPasswordCommand
from AADInternals import AADInternals
from Crypto import Random


import configparser



config = configparser.ConfigParser()
config.read('/etc/azureconf/azure.conf')


## Open connection to Syslog ##
syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_LOCAL3)

filename = config.get('common', 'path_pwdlastset_file_azure')
dict_mail_pwdlastset={}
if os.path.isfile(filename):
    dict_mail_pwdlastset = json.loads(open(filename,'r').read())

az = None
mailadmin = config.get('common', 'mailadmin')
passwordadmin = config.get('common', 'passwordadmin')

domainazure = config.get('common', 'domainazure')

proxiesconf = config.get('common', 'proxy')
if proxiesconf:
    proxies={'http':proxiesconf,'https':proxiesconf}
else:
    proxies={}




def update_password(mail, pwd, pwdlastset):

    global az
    global mailadmin
    global passwordadmin
    global proxies
    global dict_mail_pwdlastset

    try:
        if not az:
            az = AADInternals(mail=mailadmin,password=passwordadmin,proxies=proxies)
        az.set_userpassword(hashnt=pwd,userprincipalname=mail)
        syslog.syslog(syslog.LOG_WARNING, '[NOTICE] Updated password for %s' % mail)
        dict_mail_pwdlastset[str(mail)]=str(pwdlastset)
        open(filename,'w').write(json.dumps(dict_mail_pwdlastset))
    except Exception as e:
        syslog.syslog(syslog.LOG_WARNING, '[ERROR] %s : %s' % (mail,str(e)))



def run():

    global az

    param_samba = {
    'basedn' : config.get('samba', 'path'),
    'pathsamdb':'%s/sam.ldb' % config.get('samba', 'private'),
    'adbase': config.get('samba', 'base')
    }

    # SAMDB
    lp = LoadParm()
    creds = Credentials()
    creds.guess(lp)
    samdb_loc = SamDB(url=param_samba['pathsamdb'], session_info=system_session(),credentials=creds, lp=lp)
    testpawd = GetPasswordCommand()
    testpawd.lp = lp

    # Search all users
    for user in samdb_loc.search(base=param_samba['adbase'], expression=r"(&(objectClass=user)(UserPrincipalName=*))", attrs=["sAMAccountName","pwdLastSet","UserPrincipalName"]):
        mail = str(user["UserPrincipalName"])

        pwdlastset = user.get('pwdLastSet','')

        if not  mail.endswith('@' + domainazure.lower()):
            continue

        if str(pwdlastset) != dict_mail_pwdlastset.get(mail,''):

            Random.atfork()

            # Update if password different in dict mail pwdlastset
            passwordattr = 'unicodePwd'
            password = testpawd.get_account_attributes(samdb_loc,None,param_samba['basedn'],filter="(sAMAccountName=%s)" % str(user["sAMAccountName"]) ,scope=ldb.SCOPE_SUBTREE,attrs=[passwordattr],decrypt=False)
            if not passwordattr in password:
                continue
            hashnt = password[passwordattr][0].hex().upper()
            update_password(mail, hashnt, pwdlastset)
    az = None



