#!/usr/bin/env python3
#
# Script: smtools.py
#
# (c) 2025 SUSE Linux GmbH, Germany.
# GNU Public License. No warranty. No Support (only from SUSE Consulting)
#
# Version: 2025-04-04
#
# Created by: SUSE Michael Brookhuis,
#
# Description: This csi contains standard function that can be used in several other scripts
#
#
# coding: utf-8

"""
This library contains functions used in other modules
"""

import xmlrpc.client
import logging
import os
import sys
import socket
import yaml
import ssl


def load_yaml(stream):
    """
    Load YAML data.
    """
    loader = yaml.Loader(stream)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()

if not os.path.isfile(os.path.dirname(__file__) + "/configsm.yaml"):
    print("ERROR: configsm.yaml doesn't exist. Please create file")
    sys.exit(1)
else:
    with open(os.path.dirname(__file__) + '/configsm.yaml') as h_cfg:
        CONFIGSM = yaml.safe_load(h_cfg)


class SMTools:
    """
    Class to define needed tools.
    """
    error_text = ""
    error_found = False
    hostname = ""
    client = ""
    session = ""
    sid = ""
    program = "smtools"
    systemid = 0

    def __init__(self, program):
        """
        Constructor
        LOGLEVELS:
        DEBUG: info warning error debug
        INFO: info warning error
        WARNING: warning error
        ERROR: error
        """
        self.program = program
        log_dir = CONFIGSM['log_dir']
        if not os.path.exists(CONFIGSM['log_dir']):
            os.makedirs(CONFIGSM['log_dir'])
        log_name = os.path.join(log_dir, self.program + ".log")

        formatter = logging.Formatter('%(asctime)s |  {} | %(levelname)s | %(message)s'.format(self.hostname),
                                      '%d-%m-%Y %H:%M:%S')

        fh = logging.FileHandler(log_name, 'a')
        fh.setLevel(CONFIGSM['loglevel']['file'].upper())
        fh.setFormatter(formatter)

        console = logging.StreamHandler()
        console.setLevel(CONFIGSM['loglevel']['screen'].upper())
        console.setFormatter(formatter)

        self.log = logging.getLogger('')
        self.log.setLevel(logging.DEBUG)
        self.log.addHandler(console)
        self.log.addHandler(fh)

    def fatal_error(self, errtxt, return_code=1):
        """
        log fatal error and exit program
        """
        self.error_text += errtxt
        self.error_text += "\n"
        self.error_found = True
        self.log_error("{}".format(errtxt))
        self.close_program(return_code)

    def log_info(self, errtxt):
        """
        Log info text
        """
        self.log.info("{}".format(errtxt))

    def log_error(self, errtxt):
        """
        Log error text
        """
        self.log.error("{}".format(errtxt))

    def log_warning(self, errtxt):
        """
        Log error text
        """
        self.log.warning("{}".format(errtxt))

    def log_debug(self, errtxt):
        """
        Log debug text
        :param errtxt :
        :return:
        """
        self.log.debug("{}".format(errtxt))

    def close_program(self, return_code=0):
        """Close program and send mail if there is an error"""
        self.suman_logout()
        self.log_info("Finished")
        if self.error_found:
            if return_code == 0:
                sys.exit(1)
        sys.exit(return_code)

    def exit_program(self, return_code=0):
        """Exit program and send mail if there is an error"""
        self.log_info("Finished")
        if self.error_found:
            if return_code == 0:
                sys.exit(0)
        sys.exit(return_code)

    def suman_login(self):
        """
        Log in to SUSE Manager Server.
        """
        if CONFIGSM['ssl_certificate_check']:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect_ex((CONFIGSM['server'], 443))
            except:
                self.fatal_error("Unable to login to SUSE Manager server {} SOCKET".format(CONFIGSM['server']))

            self.client = xmlrpc.client.Server("https://" + CONFIGSM['server'] + "/rpc/api")
            try:
                self.session = self.client.auth.login(CONFIGSM['user'], CONFIGSM['password'])
            except:
                self.fatal_error("Unable to login to SUSE Manager server {} XMLRPC".format(CONFIGSM['server']))
        else:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.connect_ex((CONFIGSM['server'], 443))
            except:
                self.fatal_error("Unable to login to SUSE Manager server {} SOCKET".format(CONFIGSM['server']))
            context_xmlrpc = ssl.create_default_context()
            context_xmlrpc.check_hostname = False
            context_xmlrpc.verify_mode = ssl.CERT_NONE
            transport = xmlrpc.client.Transport()
            transport._ssl_wrap = lambda host, **kwargs: context_xmlrpc.wrap_socket(socket.create_connection((host, 443)), server_hostname=host)
            self.client = xmlrpc.client.Server("https://" + CONFIGSM['server'] + "/rpc/api", transport=transport)
            try:
                self.session = self.client.auth.login(CONFIGSM['user'], CONFIGSM['password'])
            except:
                self.fatal_error("Unable to login to SUSE Manager server {} XMLRPC".format(CONFIGSM['server']))


    def suman_logout(self):
        """
        Logout from SUSE Manager Server.
        """
        try:
            self.client.auth.logout(self.session)
        except xmlrpc.client.Fault:
            self.log_error("Unable to logout from SUSE Manager {}".format(CONFIGSM['server']))

    def get_server_id(self, fatal=True, name=""):
        """
        Get system Id from host
        """
        if name:
            hostname = name
        else:
            hostname = self.hostname

        all_sid = ""
        try:
            all_sid = self.client.system.getId(self.session, hostname)
        except xmlrpc.client.Fault:
            self.fatal_error("Unable to get systemid from system {}. System error, please check logs.".format(hostname))
        system_id = 0
        for x in all_sid:
            if system_id == 0:
                system_id = x.get('id')
            else:
                if fatal:
                    self.fatal_error("Duplicate system {}. Please fix and run again.".format(hostname))
                else:
                    self.log_error("Duplicate system {}. Please fix and run again.".format(hostname))
                    self.log_debug(
                        "The following system id have been found for system {}:\n{}".format(hostname, all_sid))
        if system_id == 0:
            if fatal:
                self.fatal_error(
                    "Unable to get systemid from system {}. Is this system registered?".format(hostname))
        self.systemid = system_id
        return system_id

    """
    API calls needed
    """
    def system_deletesystem(self, cleanup_type="FORCE_DELETE"):
        try:
            return self.client.system.deleteSystem(self.session, self.systemid, cleanup_type)
        except xmlrpc.client.Fault as err:
            self.log_debug('api-call: system.getseleteSystem')
            self.log_debug('Value passed: ')
            self.log_debug('  system_id:    {}'.format(self.systemid))
            self.log_debug('  cleanup_type: {}'.format(cleanup_type))
            self.log_debug("Error: \n{}".format(err))
            self.fatal_error('Unable to delete server {}.'.format(self.hostname))

    def system_create_system_record(self, system_name, ks_label, k_options, comment, net_devices):
        try:
            self.client.system.createSystemRecord(self.session, system_name, ks_label, k_options, comment,
                                                         net_devices)
        except xmlrpc.client.Fault as err:
            self.log_debug('api-call: system.createSystemRecord')
            self.log_debug('Value passed: ')
            self.log_debug('  systemName:    {}'.format(system_name))
            self.log_debug('  ksLabel:       {}'.format(ks_label))
            self.log_debug('  kOptions:      {}'.format(k_options))
            self.log_debug('  comment:       {}'.format(comment))
            self.log_debug('  netDevices:    {}'.format(net_devices))
            self.log_debug("Error: \n{}".format(err))
            self.log_error('Unable to delete server {}.'.format(self.hostname))
            return False
        return True

    def channel_software_getdetails(self, channel, no_fatal=False):
        try:
            return self.client.channel.software.getDetails(self.session, channel)
        except xmlrpc.client.Fault as err:
            if no_fatal:
                return []
            else:
                message = ('Unable to get details of channel {}.'.format(channel))
                self.log_debug('api-call: )channel.software.getDetails')
                self.log_debug("Value passed: channel {}".format(channel))
                self.log_debug("Error: \n{}".format(err))
                self.log_error(message)
                return []



    """
    API call related to kickstart.tree
    """

    def kickstart_tree_getdetails(self, label, fatal=True):
        try:
            return self.client.kickstart.tree.getDetails(self.session, label)
        except xmlrpc.client.Fault as err:
            if fatal:
                self.log_debug('api-call: kickstart.tree.getDetails')
                self.log_debug('Value passed: ')
                self.log_debug('  label: {}'.format(label))
                self.log_debug('  fatal: {}'.format(fatal))
                self.log_debug("Error: \n{}".format(err))
                message = 'Unable to get a details of distribution.'
                self.fatal_error(message)
            else:
                self.log_debug(f"api-call: kickstart.tree.getDetails. Distribution '{label}'is not present")
                return None

    def kickstart_tree_delete_tree_and_profiles(self, label, fatal=True):
        try:
            return self.client.kickstart.tree.deleteTreeAndProfiles(self.session, label)
        except xmlrpc.client.Fault as err:
            if fatal:
                self.log_debug('api-call: kickstart.tree.deleteTreeAndProfiles')
                self.log_debug('Value passed: ')
                self.log_debug('  label: {}'.format(label))
                self.log_debug('  fatal: {}'.format(fatal))
                self.log_debug("Error: \n{}".format(err))
                message = 'Unable to delete distribution and associated profiles.'
                self.fatal_error(message)
            else:
                self.log_debug(f"api-call: kickstart.tree.deleteTreeAndProfiles. Distribution '{label}' is not present")
                return None

    def kickstart_tree_create(self, label, base_path, channel_label, install_type, kernel_options, post_kernel_options):
        try:
            return self.client.kickstart.tree.create(self.session, label, base_path, channel_label,
                                                     install_type, kernel_options, post_kernel_options)
        except xmlrpc.client.Fault as err:
            self.log_debug('api-call: kickstart.tree.create')
            self.log_debug('Value passed: ')
            self.log_debug('  label:             {}'.format(label))
            self.log_debug('  basePath:          {}'.format(base_path))
            self.log_debug('  channelLabel:      {}'.format(channel_label))
            self.log_debug('  installType:       {}'.format(install_type))
            self.log_debug('  kernelOptions:     {}'.format(kernel_options))
            self.log_debug('  postKernelOptions: {}'.format(post_kernel_options))
            self.log_debug("Error: \n{}".format(err))
            message = 'Unable to create distribution.'
            self.fatal_error(message)

    def kickstart_tree_update(self, label, base_path, channel_label, install_type, kernel_options, post_kernel_options):
        try:
            return self.client.kickstart.tree.update(self.session, label, base_path, channel_label,
                                                     install_type, kernel_options, post_kernel_options)
        except xmlrpc.client.Fault as err:
            self.log_debug('api-call: kickstart.tree.update')
            self.log_debug('Value passed: ')
            self.log_debug('  label:             {}'.format(label))
            self.log_debug('  basePath:          {}'.format(base_path))
            self.log_debug('  channelLabel:      {}'.format(channel_label))
            self.log_debug('  installType:       {}'.format(install_type))
            self.log_debug('  kernelOptions:     {}'.format(kernel_options))
            self.log_debug('  postKernelOptions: {}'.format(post_kernel_options))
            self.log_debug("Error: \n{}".format(err))
            message = 'Unable to update distribution.'
            self.fatal_error(message)

    """
    API call related to kickstart
    """

    def kickstart_import_raw_file(self, profile_label, virtualization_type, kickstartable_tree_label, kickstart_file_contents):
        """
        create profile based on autoyast
        :param self:
        :param profile_label:
        :param virtualization_type:
        :param kickstartable_tree_label:
        :param kickstart_file_contents:
        :return:
        """
        self.log_info("kickstart import raw file - creating autoinstall profile")
        try:
            self.client.kickstart.importRawFile(self.session, profile_label, virtualization_type,
                                                kickstartable_tree_label, kickstart_file_contents)
        except Exception as err:
            self.log_debug("api-call: kickstart.importRawFile")
            self.log_debug("Value passed: ")
            self.log_debug('  profileLabel:                {}'.format(profile_label))
            self.log_debug('  virtualizationType:          {}'.format(virtualization_type))
            self.log_debug('  kickstartableTreeLabel:      {}'.format(kickstartable_tree_label))
            self.log_debug('  kickstartFileContents:       {}'.format(kickstart_file_contents))
            self.log_debug(f"Error: \n{err}")
            self.log_error(f"Error while creating profile. Error: \n{err}")
            return False
        return True

    def kickstart_list_kickstarts(self):
        """
        List all kickstarts
        :return:
        """
        self.log_info("kickstart list kickstarts")
        result = []
        try:
            result = self.client.kickstart.listKickstarts(self.session)
        except Exception as err:
            self.log_debug("api-call: kickstart.listKickstarts")
            self.log_debug(f"Error: \n{err}")
            self.log_error(f"Error while getting list of profiles. Error: \n{err}")
            return result
        return result

    def kickstart_delete_profile(self, ks_label):
        """
        delete profile
        :param self:
        :param ks_label:
        :return:
        """
        self.log_info("kickstart delete profile")
        try:
            self.client.kickstart.deleteProfile(self.session, ks_label)
        except Exception as err:
            self.log_debug("api-call: kickstart.importRawFile")
            self.log_debug("Value passed: ")
            self.log_debug('  ksLabel:                {}'.format(ks_label))
            self.log_debug(f"Error: \n{err}")
            self.log_error(f"Error while deleting profile. Error: \n{err}")
            return False
        return True