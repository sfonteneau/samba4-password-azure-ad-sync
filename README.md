Installation
========================

Test
=====
 - pip3 install azure-graphrbac
 - git clone https://github.com/sfonteneau/samba4-password-azure-ad-sync.git
 - mv samba4-password-azure-ad-sync /opt/sync-azure
 - mkdir /etc/azureconf/
 - cd /opt/sync-azure
 - cp -f azure.conf /etc/azureconf/
 - Configure /etc/azureconf/azure.conf

You can try like this:

python3 /opt/sync-azure/sync_password_azure.py
