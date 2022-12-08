#!/usr/bin/python

# Google Apps Passwords Sync for Samba4
# author Johan Johansson johan@baboons.se
# Free to use!

import time
import sync_password_azure_lib
import os.path
import sys

while True:
    sync_password_azure_lib.run()
    time.sleep(60)