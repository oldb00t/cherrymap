#!/usr/bin/env python
import xml.etree.cElementTree as ET
from libnmap.parser import NmapParser
from hashlib import md5
import os
import re
import base64
import argparse

# Argpars
parser = argparse.ArgumentParser()
parser.add_argument("-ah", "--allhosts", action="store_true",
                    help="add all hosts even when no open ports are detected")
parser.add_argument("-ap", "--allports", action="store_true",
                    help="add ports closed or filtered")
parser.add_argument("-", "--all", action="store_true",
                    help="same as '-ah -ap'")
parser.add_argument("-s", "--sparta", action="store_true",
                    help="folder is sparta output (will try to import other tool outputs)")
parser.add_argument("-m", "--merge", type=str,
                    help="existing file to copy data from")
parser.add_argument("-o", "--output", type=str, default="cherrymap.ctd",
                    help="output file name (default cherrymap.ctd)")
parser.add_argument("folder",
                    help="folder where nmap outputs are stored")
args = parser.parse_args()

# Cleanup path and modify for Sparta input. Should verify that folder exists.
if args.folder.endswith("/"):
    path=args.folder
else:
    path=args.folder+"/"

if args.sparta:
    nmap_folder = path+"nmap/"
else:
    nmap_folder = path

# Start cherrytree file.
# If merge, import data from existing file, otherwise create new tree.
uid=1
root = ET.Element("cherrytree")
node = ET.SubElement(root, "node", custom_icon_id="0", foreground="",
                     is_bold="False", name="Hosts",
                     prog_lang="custom-colors", readonly="False",
                     tags="", unique_id=str(uid))
uid=uid+1

if args.sparta and os.path.isdir(path+"screenshots/"):
    # Get all file names from the screenshots folder to search later.
    all_screenshot_files = [f for f in os.listdir(path+"screenshots/") if os.path.isfile(path+"screenshots/"+f)]
    all_tool_output_files = []
    # Get all file names from the other tool output folders to search later.
    #for tool_folder in os.listdir(path):
    #    if tool_folder <> "nmap" and tool_folder <> screenshot:
    #        all_tool_output_files += os.listdir(path+tool_folder+"/")

# Read all nmap files and write into tree object.
for filename in os.listdir(nmap_folder):
    if not filename.endswith('.xml'): continue
    try:
        rep = NmapParser.parse_fromfile(nmap_folder+filename)
    except:
        continue

    for _host in rep.hosts:
        if (_host.is_up() and len(_host.services)>0) or args.allhosts or args.all:
            # If a node already exits for the host, use it, otherwise create one.
            try:
                host = node.findall('./node[@name="' + _host.address + '"]')[0]
                
            except:
                host = ET.SubElement(node, "node", foreground="", is_bold="False",
                                     name=_host.address, prog_lang="custom-colors",
                                     readonly="False", tags="", unique_id=str(uid))
                uid=uid+1

                # Need this part to run for all files and dedupe results.
                fing = ET.SubElement(host, "rich_text")
                fp = str(_host.hostnames)+_host.os_fingerprint+"\n"
                if _host.os_fingerprinted:
                    for os in _host.os_match_probabilities():
                        fp = fp + os.name + "\n"
                fing.text=fp
                
            for  _service in _host.services:
                if _service.open() or args.allports or args.all:
                    color=""
                    if not _service.open():
                        color="#ff0000"
                    # If there is already a node for the service, use it, otherwise create one.
                    try:
                        service = host.findall('./node[@name="' + str(_service.port) + "/" +
                                               _service.protocol + " - " + _service.service + '"]')[0]
                    except:
                        service = ET.SubElement(host, "node", foreground=color, is_bold="False",
                                                name=str(_service.port) + "/" + _service.protocol +
                                                " - " + _service.service, prog_lang="custom-colors",
                                                readonly="False", tags="", unique_id=str(uid))
                        uid=uid+1
                        ET.SubElement(service, "rich_text", style="italic", weight="heavy").text="Banner:\n"
                        ET.SubElement(service, "rich_text").text=_service.banner+"\n\n\n"
                        ET.SubElement(service, "rich_text", style="italic", weight="heavy").text="Scripts & Tools:\n"
                    if args.sparta:
                        # Add all applicable screenshots to the service node. Need to fix dedupe.
                        regex = re.compile(r'.*-screenshot-' + str(_host.address) + '-' + str(_service.port) + '.png')
                        files = filter(regex.search, all_screenshot_files)
                        if len(files) > 0:
                            screenshots = []
                            hashes = []
                            for screenshot in files:
                                with open(path+"screenshots/"+screenshot, "rb") as image_file:
                                    encode_string = base64.b64encode(image_file.read())
                                    hashed_string = md5(encode_string).hexdigest()
                                if len(encode_string) > 0 and hashed_string not in hashes:
                                    screenshots += [encode_string]
                                    hashes += [hashed_string]
                            if len(screenshots) > 0:
                                for screenshot in screenshots:
                                    ET.SubElement(service, "encoded_png", char_offset="100").text=screenshot

                    # Add all the NMap script data to the service node.
                    for scr in _service.scripts_results:
                        try:
                            ET.SubElement(service, "rich_text", weight="heavy").text=scr['id']+"\n"
                        except:
                            continue
                        try:
                            ET.SubElement(service, "rich_text").text=scr['output']+"\n"
                        except:
                            continue
                    # Add all the other tools data to the service node.
                        

tree = ET.ElementTree(root)
tree.write(args.output)
