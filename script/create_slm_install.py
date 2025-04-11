#!/usr/bin/env python3
#
# create_slm_install.pt
#
# (c) 2025 SUSE y.
# GNU Public License. No warranty. No Support
#
# Version: 2025-04-04
#
# Created by: SUSE Michael Brookhuis

import argparse
import datetime
import os
import xmlrpc.client
import subprocess
import smtools
import time

__smt = None







def main():
    """
    Main function
    """
    try:
        global smt
        parser = argparse.ArgumentParser(description="Update the give system.")
        parser.add_argument('-s', '--server', help='file containing the server or servers information. Required')
        parser.add_argument("-f", "--force", default=False, help="If profile, combustion or ignition exist, delete first. Otherwise generate an error")
        parser.add_argument('--version', action='version', version='%(prog)s 0.1.0, April 4, 2025')
        args = parser.parse_args()
        if not args.server:
            smt = smtools.SMTools("create_slm_install")
            smt.log_error("The option --server is mandatory. Exiting script")
            smt.exit_program(1)
        else:
            smt = smtools.SMTools("create_slm_install", "", True)
        # login to suse manager
        smt.log_info("Start")
        smt.log_debug("The following arguments are set: ")
        smt.log_debug(args)
        smt.suman_login()
        smt.set_hostname(args.server)
        #update_server(args)
        smt.close_program()
    except Exception as err:
        smt.log_debug("general error:")
        smt.log_debug(err)
        raise

if __name__ == "__main__":
    SystemExit(main())