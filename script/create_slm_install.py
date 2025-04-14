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
import ipaddress
import os

import smtools

#from script.smtools import CONFIGSM

__smt = None



def read_config_servers(config_servers):
    """
    Read the config of all the servers
    :param config_servers:
    :return:
    """

    if not os.path.isfile(os.path.dirname(__file__) + "/" + config_servers):
        smt.fatal_error("ERROR: {} doesn't exist.", config_servers)
    else:
        with open(os.path.dirname(__file__) + "/" + config_servers) as h_cfg:
            configs = smtools.load_yaml(h_cfg)
    smt.log_info(configs)
    return configs

def validate_data(srv_data):
    """
    Check mandatory date:
    - ip --> valid ip
    - netmask --> prefix or x.x.x.x --> change to prefix
    - dnsserver --> valid ips
    - gateway --> valid ip and is it part of the same network as ip
    - template --> does it exist
    :param srv_data:
    :return:
    """
    try:
        ipaddress.IPv4Address(srv_data['ipaddress'])
    except ipaddress.AddressValueError:
        return f"Given IP address {srv_data['ipaddress']} is invalid"
    except KeyError:
        return f"Mandatory parameter \"ipaddress\" not given"

    try:
        for dns in srv_data['dnsserver']:
            try:
                ipaddress.IPv4Address(dns)
            except ipaddress.AddressValueError:
                return f"Given DNS IP address {dns} is invalid"
    except KeyError:
       return f"Mandatory parameter \"dnsserver\" not given"

    try:
        netmask = srv_data['subnetmask']
    except KeyError:
        return f"Mandatory parameter \"subnetmask\" not given"

    if "." in {srv_data['subnetmask']}:
        try:
            netmask_new = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
        except ipaddress.NetmaskValueError:
            return f"Given subnetmask {srv_data['subnetmask']} is invalid"
        netmask = netmask_new

    try:
        network = ipaddress.IPv4Network(f"{srv_data['ipaddress']}/{netmask}", strict=False)
    except ipaddress.NetmaskValueError:
        return f"Given subnetmask {srv_data['subnetmask']} is invalid"
    except KeyError:
        return f"Mandatory parameter \"subnetmask\" not given"

    try:
        ipaddress.IPv4Address(srv_data['gateway'])
    except ipaddress.AddressValueError:
        return f"Given gateway IP address {srv_data['gateway']} is invalid"
    except KeyError:
        return f"Mandatory parameter \"gateway\" not given"
    if not ipaddress.ip_address(srv_data['gateway']) in ipaddress.ip_network(network):
        return f"Given gateway IP address {srv_data['gateway']} is not in same network {srv_data['ipaddress']}/{srv_data['subnetmask']}"

    try:
        fn_c = smtools.CONFIGSM['template_dir'] + "/combustion/" + srv_data['template_combustion']
    except KeyError:
        return f"Mandatory parameter \"template_combustion\" not given"
    if not os.path.isfile(fn_c):
        smt.fatal_error(f"ERROR: {fn_c} doesn't exist.")

    try:
        fn_i = smtools.CONFIGSM['template_dir'] + "/ignition/" + srv_data['template_ignition']
    except KeyError:
        return f"Mandatory parameter \"template_ignition\" not given"
    if not os.path.isfile(fn_i):
        smt.fatal_error(f"ERROR: {fn_i} doesn't exist.")

def write_combustion(server, srv_data, delete_old):
    """
    Write combustion script.
    Also check if file is already present. If file is present, generate error
    when delete_old is false or remove file when delete_old is true.
    :param server:
    :param srv_data:
    :param delete_old:
    :return:
    """
    try:
        script_dir = '%s/' % smtools.CONFIGSM['server_types'][srv_data['server_type']]['installation_path'].rstrip('/')
    except KeyError:
        return f"In configsm no or invalid definition available for server type {srv_data['server_type']}"
    combustion_script = script_dir + "combustion/" + server + ".sh"
    err = create_file(script_dir, combustion_script, delete_old)
    if err:
        return err

    if "." in {srv_data['subnetmask']}:
        netmask = ipaddress.IPv4Network(f"0.0.0.0/{srv_data['subnetmask']}").prefixlen
    else:
        netmask = srv_data['subnetmask']

    parameters_to_add = [f"IPADDRESS={srv_data['ipaddress']}",
                         f"NETWORK={netmask}",
                         f"GATEWAY={srv_data['gateway']}", f"DNSSERVER={srv_data['dnsserver']}",
                         f"HOSTNAME={server}.{srv_data['domain']}"]
    for parameter, value in srv_data['parameters'].items():
        parameters_to_add.append(f"{parameter}={value}")
    fn_c = smtools.CONFIGSM['template_dir'] + "/combustion/" + srv_data['template_combustion']

    err = insert_lines_between_markers(fn_c, combustion_script, parameters_to_add)
    if err:
        return err
    smt.log_debug(f"For server {server} create the following combustion file successful: {combustion_script}.")

def write_ignition(server, srv_data, delete_old):
    """
    Write ignition script.
    Also check if file is already present. If file is present, generate error
    when delete_old is false or remove file when delete_old is true.

    NOTE: currently it is only implemented to change the hostname.

    :param server:
    :param srv_data:
    :param delete_old:
    :return:
    """
    try:
        script_dir = '%s/' % smtools.CONFIGSM['server_types'][srv_data['server_type']]['installation_path'].rstrip('/')
    except KeyError:
        return f"In configsm no or invalid definition available for server type {srv_data['server_type']}"
    ignition_script = script_dir + "ignition/" + server + ".ign"
    err = create_file(script_dir, ignition_script, delete_old)
    if err:
        return err
    hostname = server + "." + srv_data['domain']
    fn_i = smtools.CONFIGSM['template_dir'] + "/ignition/" + srv_data['template_combustion']
    with open(fn_i,'r') as f:
        newlines = []
        for line in f.readlines():
            newlines.append(line.replace('REPL_HOSTNAME', hostname))
    with open(ignition_script, 'w') as f:
        for line in newlines:
            f.write(line)
    smt.log_debug(f"For server {server} create the following ignition file successful: {ignition_script}.")

def create_file(script_dir, script_file, delete_old):
    if not os.path.isdir(script_dir):
        os.mkdir(script_dir)
    if os.path.isfile(script_file):
        if delete_old:
            os.remove(script_file)
        else:
            return f"file {script_file} already exists and force deletion is not set"

def insert_lines_between_markers(file_template, file_target, lines_to_insert, start_marker="#-- Start", end_marker="#-- End"):
    """
    Inserts lines between specified start and end markers in a file.

    Args:
        filepath (str): The path to the file.
        lines_to_insert (list of str): A list of strings to insert.
        start_marker (str, optional): The start marker. Defaults to "#-- Start".
        end_marker (str, optional): The end marker. Defaults to "#-- End".
        :param end_marker:
        :param start_marker:
        :param lines_to_insert:
        :param file_target:
        :param file_template:
    """
    try:
        with open(file_template, "r") as f:
            file_lines = f.readlines()
        start_index = -1
        end_index = -1
        for i, line in enumerate(file_lines):
            if start_marker in line:
                start_index = i + 1  # Insert after the start marker
            if end_marker in line:
                end_index = i
        if start_index == -1 or end_index == -1 or start_index > end_index:
            return f"Markers not found or in incorrect order in {file_template}."
        # Insert lines, handling potential overlap
        new_lines = file_lines[:start_index] + [line + "\n" if not line.endswith("\n") else line for line in lines_to_insert] + file_lines[end_index:]
        with open(file_target, "w") as f:
            f.writelines(new_lines)

    except Exception as e:
        return f"An error occurred: {e}"

def create_profile_autoyast(server, srv_data, delete_old):
    """
    This will create the needed profile in autoyast.
    The following kernel options should be set:
    - rd.kiwi.oem.installdevice=/dev/vda
    -
    :param server:
    :param srv_data:
    :param delete_old:
    :return:
    """


    return

def create_distribution_autoyast(server, srv_data, delete_old):
    """
    This will create the needed distribution in autoyast.

    If the distribution exist, validate the data and if different do:
    - delete_old == true --> make the needed changes
    - delete_old == false --> exit with error
    If the distribution doesn't exist, create it.

    :param server:
    :param srv_data:
    :param delete_old:
    :return:
    """


    return



def start_slm_creating(config_servers, delete_old):
    """
    The following has to be done:
    - read config file
    - loop through each entry
      - validating content
      - create information needed

    :param config_servers:
    :param delete_old:
    :return:
    """
    configs = read_config_servers(config_servers)
    for server, srv_data in configs.items():
        err = validate_data(srv_data)
        if err:
            smt.fatal_error(f"ERROR: {err} for server {server}")
        err = write_combustion(server, srv_data, delete_old)
        if err:
            smt.fatal_error(f"ERROR: {err} for server {server}")
        err = write_ignition(server, srv_data, delete_old)
        if err:
            smt.fatal_error(f"ERROR: {err} for server {server}")
        err = create_distribution_autoyast(server, srv_data, delete_old)
        if err:
            smt.fatal_error(f"ERROR: {err} for server {server}")
        err = create_profile_autoyast(server, srv_data, delete_old)
        if err:
            smt.fatal_error(f"ERROR: {err} for server {server}")


def main():
    """
    Main function
    """
    try:
        global smt
        parser = argparse.ArgumentParser(description="Install give system.")
        parser.add_argument('-c', '--config', help='file containing the server or servers information. Required')
        parser.add_argument("-d", "--delete", action='store_true', default=False, help="If profile, combustion or ignition exist, delete first. Otherwise generate an error")
        parser.add_argument('--version', action='version', version='%(prog)s 0.1.0, April 4, 2025')
        args = parser.parse_args()
        if not args.config:
            print("The option --config is mandatory. Exiting script")
            smt.exit_program(1)
        else:
            smt = smtools.SMTools("create_slm_install")
        # login to suse manager
        smt.log_info("Start")
        smt.log_debug("The following arguments are set: ")
        smt.log_debug(args)
        # smt.suman_login()
        start_slm_creating(args.config, args.delete)
    except Exception as err:
        smt.log_error("An unexpected error occurred. Check log file (in debug mode) for more information.")
        smt.log_debug("general error:")
        smt.log_debug(err)
        smt.exit_program(1)

if __name__ == "__main__":
    SystemExit(main())