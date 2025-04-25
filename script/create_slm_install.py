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
import re
import time

import yaml
import smtools

__smt = None

class NetworkDevice:
    def __init__(self, name, mac, ip, dnsname):
        self.name = name
        self.mac = mac
        self.ip = ip
        self.dnsname = dnsname


def read_config_servers(config_servers):
    """
    Read the config of all the servers
    :param config_servers:
    :return:
    """
    smt.log_debug("start read_config_servers")
    if not os.path.isfile(os.path.dirname(__file__) + "/" + config_servers):
        smt.fatal_error("ERROR: {} doesn't exist.", config_servers)
    else:
        with open(os.path.dirname(__file__) + "/" + config_servers) as h_cfg:
            configs = yaml.safe_load(h_cfg)
    return configs

def validate_data(server, srv_data, delete_old):
    """
    Check mandatory date:
    - ip --> valid ip
    - netmask --> prefix or x.x.x.x --> change to prefix
    - dnsserver --> valid ips
    - gateway --> valid ip and is it part of the same network as ip
    - template --> does it exist
    :param server:
    :param srv_data:
    :param delete_old:
    :return:
    """
    smt.log_debug("start validate_data")
    # check if system is not already in SMLM. If and delete_old is true, delete system. If and delete_old is false
    # throw an error.
    try:
        if not "." in srv_data['domain']:
            return f"The given domain {srv_data['domain']} has the wrong format"
    except KeyError:
        return f"Mandatory parameter \"domain\" not given"
    hostname = f"{server}.{srv_data['domain']}"
    system_id = smt.get_server_id(False, hostname)
    if system_id > 0:
        if delete_old:
            smt.system_deletesystem()
            smt.log_debug(f"System {server} was present in SUSE Manager and has been deleted ")
        else:
            return f"Server {server} is present and force delete is false"

    # check if IP Address is valid
    try:
        ipaddress.IPv4Address(srv_data['ipaddress'])
    except ipaddress.AddressValueError:
        return f"Given IP address {srv_data['ipaddress']} is invalid"
    except KeyError:
        return f"Mandatory parameter \"ipaddress\" not given"

    # check if MAC-address is given, if this is valid.
    if "mac_address" in srv_data:
        mac_regex = re.compile(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$|'
                               r'^([0-9A-Fa-f]{4}\.){2}([0-9A-Fa-f]{4})$')
        if not mac_regex.match(srv_data['mac_address']):
            return f"Given MAC-address {srv_data['mac_address']} is invalid"


    # Check if the IPs of the DNSSERVER are valid IPs
    try:
        for dns in srv_data['dnsserver']:
            try:
                ipaddress.IPv4Address(dns)
            except ipaddress.AddressValueError:
                return f"Given DNS IP address {dns} is invalid"
    except KeyError:
       return f"Mandatory parameter \"dnsserver\" not given"

    # Check subnetmaks and convert to cidr for later
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

    # Check if IP address of gateway is valid and if it is in the same network as IP Address
    try:
        ipaddress.IPv4Address(srv_data['gateway'])
    except ipaddress.AddressValueError:
        return f"Given gateway IP address {srv_data['gateway']} is invalid"
    except KeyError:
        return f"Mandatory parameter \"gateway\" not given"
    if not ipaddress.ip_address(srv_data['gateway']) in ipaddress.ip_network(network):
        return f"Given gateway IP address {srv_data['gateway']} is not in same network {srv_data['ipaddress']}/{srv_data['subnetmask']}"

    # check if combustion template is present
    if not "template_dir" in smtools.CONFIGSM:
        return "The parameter \"template_dir\" is not present in configsm.yaml"
    try:
        fn_c = smtools.CONFIGSM['template_dir'] + "/combustion/" + srv_data['template_combustion']
    except KeyError:
        return f"Mandatory parameter \"template_combustion\" not given"
    if not os.path.isfile(fn_c):
        smt.fatal_error(f"ERROR: {fn_c} doesn't exist.")

    # check if ignition template is present
    try:
        fn_i = smtools.CONFIGSM['template_dir'] + "/ignition/" + srv_data['template_ignition']
    except KeyError:
        return f"Mandatory parameter \"template_ignition\" not given"
    if not os.path.isfile(fn_i):
        smt.fatal_error(f"ERROR: {fn_i} doesn't exist.")

    # Check if the given servertype is defined and part of configsm.yaml
    try:
        server_type = srv_data['server_type']
    except KeyError:
        return f"The given Mandatory parameter \"server_type\" not given"
    if not server_type in smtools.CONFIGSM['server_types']:
        return f"The given {server_type} is not present in the section \"server_types\" of configsm.yaml"

    # check if distribution_assigned_channel exists
    try:
        dist_channel = smtools.CONFIGSM['server_types'][server_type]['distribution_assigned_channel']
    except KeyError:
        return f"Mandatory parameter \"distribution_assigned_channel\" not given in section \"server_types:{server_type}\"configsm.yaml"
    if not smt.channel_software_getdetails(dist_channel, True):
        return f"The given channel {dist_channel} for parameter \"distribution_assigned_channel\" doesn't exist"

    #check if other needed parameters exist in server data
    if not "install_on_disk" in srv_data:
        return f"Mandatory parameter \"install_on_disk\" not given"

    # check if other needed parameters exist in configsm.yaml
    need_parameters = ["image_path", "installation_path", "distribution_kernel_options", "distribution_tree_path"]
    for param in need_parameters:
        if not param in smtools.CONFIGSM['server_types'][server_type]:
            return f"Mandatory parameter \"{param}\" not given in section \"server_types:{server_type}\" in configsm.yaml"



    smt.log_debug(f"Validation of data for {server} completed")



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
    smt.log_debug("start write_combustion")
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
                         f"HOSTNAME={server}.{srv_data['domain']}", f"DOMAIN={srv_data['domain']}"]
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
    smt.log_debug("start write_ignition")
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
    """

    :param script_dir:
    :param script_file:
    :param delete_old:
    :return:
    """
    smt.log_debug("start create_file")
    if not os.path.isdir(script_dir):
        os.mkdir(script_dir)
    if os.path.isfile(script_file):
        if delete_old:
            os.remove(script_file)
            return None
        else:
            return f"file {script_file} already exists and force deletion is not set"
    return None


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
    smt.log_debug("start insert_lines_between_markers")
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
    smt.log_debug("start create_profile_autoyast")
    result = smt.kickstart_list_kickstarts()
    if result:
        has_target = any('label' in item and item['label'] == server for item in result)
        if has_target:
            if delete_old:
                if not smt.kickstart_delete_profile(server):
                    return f"Error: deleting existing profile for {server} failed"
            else:
                return f"profile {server} already exists and force deletion is not set"
    if not smt.kickstart_import_raw_file(server, "none", server, ""):
        return f"Error: creating profile for {server} failed"
    if "mac_address" in srv_data:
        net_devices = [NetworkDevice("eth0", srv_data["mac_address"], "", "")]
        if not smt.system_create_system_record(server, server, "", "", net_devices):
            return f"Error: creating cobbler entry for {server} failed"

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
    smt.log_debug("start create_distribution_autoyast")
    try:
        dist_channel = smtools.CONFIGSM['server_types'][srv_data['server_type']]['distribution_assigned_channel']
        dist_tree = smtools.CONFIGSM['server_types'][srv_data['server_type']]['distribution_tree_path']
        dist_path = smtools.CONFIGSM['server_types'][srv_data['server_type']]['image_path']
    except KeyError:
        return f"Error: one of more of the distribution options for server type {srv_data['server_type']} is missing"
    distribution_label = server
    dist_kernel = (smtools.CONFIGSM['server_types'][srv_data['server_type']]['distribution_kernel_options'] +
                   f" ignition.config.url={dist_path}/ignition/{server}.ign" +
                   f" combustion.url={dist_path}/combustion/{server}.sh" 
                   f" rd.kiwi.oem.installdevice={srv_data['install_on_disk']}")

    result = smt.kickstart_tree_getdetails(distribution_label, False)
    if result:
        if delete_old:
            smt.kickstart_tree_update(distribution_label, dist_tree, dist_channel, "sles15generic",
                                          dist_kernel, "")
    else:
        smt.kickstart_tree_create(distribution_label, dist_tree, dist_channel, "sles15generic",
                                  dist_kernel, "")
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
    smt.log_debug("start start_slm_creating")
    configs = read_config_servers(config_servers)
    for server, srv_data in configs.items():
        smt.suman_login()
        err = validate_data(server, srv_data, delete_old)
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
            smt.suman_logout()
            smt.fatal_error(f"ERROR: {err} for server {server}")
        time.sleep(smtools.CONFIGSM['wait_between_events_check'])
        err = create_profile_autoyast(server, srv_data, delete_old)
        if err:
            smt.suman_logout()
            smt.fatal_error(f"ERROR: {err} for server {server}")
        smt.suman_logout()

def perform_cleanup(server):
    """
    Remove all entries for aut
    :param server:
    :return:
    """
    smt.log_debug("start perform_cleanup")
    for server_type in smtools.CONFIGSM['server_types'].values():
        try:
            script_dir = '%s/' % server_type['installation_path'].rstrip('/')
        except KeyError:
            smt.log_error( f"In configsm no or invalid definition available for server type {server_type}")
            continue
        script = script_dir + "ignition/" + server + ".ign"
        try:
            os.remove(script)
        except OSError:
            pass
        script = script_dir + "combustion/" + server + ".sh"
        try:
            os.remove(script)
        except OSError:
            pass
    smt.suman_login()
    smt.kickstart_tree_delete_tree_and_profiles(server, False)
    smt.suman_logout()

def main():
    """
    Main function
    """
    try:
        global smt
        parser = argparse.ArgumentParser(description="Install give system.")
        parser.add_argument('-f', '--file', help='file containing the server or servers information.')
        parser.add_argument("-d", "--delete", action='store_true', default=False, help="If profile, combustion or ignition exist, delete first. Otherwise generate an error")
        parser.add_argument("-c", "--cleanup", help="Cleanup the install files of the given server.")

        parser.add_argument('--version', action='version', version='%(prog)s 0.1.0, April 4, 2025')
        args = parser.parse_args()

        smt = smtools.SMTools("create_slm_install")
        smt.log_info("Start")
        smt.log_debug("The following arguments are set: ")
        smt.log_debug(args)

        if args.cleanup:
            perform_cleanup(args.cleanup)
        else:
            if not args.file:
                print("The option --file is mandatory. Exiting script")
                smt.exit_program(1)
            start_slm_creating(args.file, args.delete)
    except Exception as err:
        smt.log_error("An unexpected error occurred. Check log file (in debug mode) for more information.")
        smt.log_debug("general error:")
        smt.log_debug(err)
        smt.exit_program(1)

if __name__ == "__main__":
    SystemExit(main())