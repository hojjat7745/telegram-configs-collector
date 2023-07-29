#import requirement libraries
import os
import wget
import json

import math
import random

import jdatetime
from datetime import datetime, timezone, timedelta

#import web-based libraries
import html
import requests
from bs4 import BeautifulSoup

#import regex and encoding libraries
import re
import base64

#import custom python script
from title import check_modify_config


# Create the geoip-lite folder if it doesn't exist
if not os.path.exists('./geoip-lite'):
    os.mkdir('./geoip-lite')

if os.path.exists('./geoip-lite/geoip-lite-country.mmdb'):
    os.remove('./geoip-lite/geoip-lite-country.mmdb')

# Download the file and rename it
url = 'https://git.io/GeoLite2-Country.mmdb'
filename = 'geoip-lite-country.mmdb'
wget.download(url, filename)

# Move the file to the geoip folder
os.rename(filename, os.path.join('./geoip-lite', filename))


# Clean up unmatched file
with open("./splitted/no-match", "w") as no_match_file:
    no_match_file.write("#Non-Adaptive Configurations\n")


# Load and read last date and time update
with open('./last update', 'r') as file:
    last_update_datetime = file.readline()
    last_update_datetime = datetime.strptime(last_update_datetime, '%Y-%m-%d %H:%M:%S.%f%z')

# Write the current date and time update
with open('./last update', 'w') as file:
    current_datetime_update = datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30)))
    file.write(f'{current_datetime_update}')

print(f"Latest Update: {last_update_datetime.strftime('%a, %d %b %Y %H:%M %Z')}\nCurrent Update: {current_datetime_update.strftime('%a, %d %b %Y %H:%M %Z')}")


def json_load(path):
    # Open and read the json file
    with open(path, 'r') as file:
        # Load json file content into list
        list_content = json.load(file)
    # Return list of json content
    return list_content


def tg_channel_messages(channel_user):
    try:
        # Retrieve channels messages
        response = requests.get(f"https://t.me/s/{channel_user}")
        soup = BeautifulSoup(response.text, "html.parser")
        # Find all telegram widget messages
        div_messages = soup.find_all("div", class_="tgme_widget_message")
        # Return list of all messages in channel
        return div_messages
    except Exception as exc:
        pass


def find_matches(text_content):
    # Initialize configuration type patterns
    pattern_shadowsocks = r"(?<![\w-])(ss://[^\s<>#]+)"
    pattern_trojan = r"(?<![\w-])(trojan://[^\s<>#]+)"
    pattern_vmess = r"(?<![\w-])(vmess://[^\s<>#]+)"
    pattern_vless = r"(?<![\w-])(vless://(?:(?!=reality)[^\s<>#])+(?=[\s<>#]))"
    pattern_reality = r"(?<![\w-])(vless://[^\s<>#]+?security=reality[^\s<>#]*)"

    # Find all matches of patterns in text
    matches_shadowsocks = re.findall(pattern_shadowsocks, text_content)
    matches_trojan = re.findall(pattern_trojan, text_content)
    matches_vmess = re.findall(pattern_vmess, text_content)
    matches_vless = re.findall(pattern_vless, text_content)
    matches_reality = re.findall(pattern_reality, text_content)

    # Iterate over matches to subtract titles
    for index, element in enumerate(matches_vmess):
        matches_vmess[index] = re.sub(r"#[^#]+$", "", html.unescape(element))

    for index, element in enumerate(matches_shadowsocks):
        matches_shadowsocks[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#SHADOWSOCKS")

    for index, element in enumerate(matches_trojan):
        matches_trojan[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#TROJAN")

    for index, element in enumerate(matches_vless):
        matches_vless[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#VLESS")

    for index, element in enumerate(matches_reality):
        matches_reality[index] = (re.sub(r"#[^#]+$", "", html.unescape(element))+ f"#REALITY")

    matches_shadowsocks = [x for x in matches_shadowsocks if "…" not in x]
    matches_trojan = [x for x in matches_trojan if "…" not in x]
    matches_vmess = [x for x in matches_vmess if "…" not in x]
    matches_vless = [x for x in matches_vless if "…" not in x]
    matches_reality = [x for x in matches_reality if "…" not in x]

    return matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality


def tg_message_time(div_message):
    # Retrieve channel message info
    div_message_info = div_message.find('div', class_='tgme_widget_message_info')
    # Retrieve channel message datetime
    message_datetime_tag = div_message_info.find('time')
    message_datetime = message_datetime_tag.get('datetime')

    # Change message datetime type into object and convert into Iran datetime
    datetime_object = datetime.fromisoformat(message_datetime)
    datetime_object = datetime.astimezone(datetime_object, tz = timezone(timedelta(hours = 3, minutes = 30)))

    # Retrieve now datetime based on Iran timezone
    datetime_now = datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30)))

    # Return datetime object, current datetime based on Iran datetime and delta datetime
    return datetime_object, datetime_now, datetime_now - datetime_object


def tg_message_text(div_message):
    # Retrieve message text class from telegram messages widget
    div_message_text = div_message.find("div", class_="tgme_widget_message_text")
    text_content = div_message_text.prettify()
    text_content = re.sub(r"<code>([^<>]+)</code>", r"\1",
                          re.sub(r"<a[^<>]+>([^<>]+)</a>", r"\1",re.sub(r"\s*", "", text_content),),)
    # Return text content
    return text_content


# Load telegram channels usernames
telegram_channels = json_load('telegram channels.json')

# Initial channels messages array
channel_messages_array = list()

# Iterate over all public telegram chanels and store twenty latest messages
for channel_user in telegram_channels:
    try:
        print(f'{channel_user}')
        # Iterate over Telegram channels to Retrieve channel messages and extend to array
        div_messages = tg_channel_messages(channel_user)
        for div_message in div_messages:
            datetime_object, datetime_now, delta_datetime_now = tg_message_time(div_message)
            if datetime_object > last_update_datetime:
                print(f"\t{datetime_object.strftime('%a, %d %b %Y %H:%M %Z')}")
                channel_messages_array.append(div_message)
    except Exception as exc:
        continue

# Print out total new messages counter
print(f"\nTotal New Messages From {last_update_datetime.strftime('%a, %d %b %Y %H:%M %Z')} To {current_datetime_update.strftime('%a, %d %b %Y %H:%M %Z')} : {len(channel_messages_array)}\n")


# Initial arrays for protocols
array_shadowsocks = list()
array_trojan = list()
array_vmess = list()
array_vless = list()
array_reality = list()

for message in channel_messages_array:
    try:
        # Iterate over channel messages to extract text content
        text_content = tg_message_text(message)
        # Iterate over each message to extract configuration protocol types and subscription links
        matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality = find_matches(text_content)

        # Extend protocol type arrays and subscription link array
        array_shadowsocks.extend(matches_shadowsocks)
        array_trojan.extend(matches_trojan)
        array_vmess.extend(matches_vmess)
        array_vless.extend(matches_vless)
        array_reality.extend(matches_reality)

    except Exception as exc:
        continue


def html_content(html_address):
    # Retrieve subscription link content
    response = requests.get(html_address, timeout = 5)
    soup = BeautifulSoup(response.text, 'html.parser').text
    return soup


def is_valid_base64(string_value):
    try:
        # Decode the string using base64
        byte_decoded = base64.b64decode(string_value)
        # Encode the decoded bytes back to base64 and compare to the original string
        return base64.b64encode(byte_decoded).decode("utf-8") == string_value
    except:
        return False


def decode_string(content_array):
    # Initilize arrays for encoded and unencoded strings
    decoded_strings = list()
    # Decode strings and append to array
    for element in content_array:
        if is_valid_base64(element):
            element = base64.b64decode(element).decode("utf-8")
        decoded_strings.append(element)
    return decoded_strings


def decode_vmess(vmess_config):
    try:
        encoded_config = re.sub(r"vmess://", "", vmess_config)
        decoded_config = base64.b64decode(encoded_config).decode("utf-8")
        decoded_config_dict = json.loads(decoded_config)
        
        decoded_config_dict["ps"] = f"VMESS"
        decoded_config = json.dumps(decoded_config_dict)

        encoded_config = decoded_config.encode('utf-8')
        encoded_config = base64.b64encode(encoded_config).decode('utf-8')
        encoded_config = f"vmess://{encoded_config}"
        return encoded_config
    except:
        return None


# Load subscription links
subscription_links = json_load('subscription links.json')

# Initial links contents array decoded content array
array_links_content = list()
array_links_content_decoded = list()

for url_link in subscription_links:
    try:
        # Retrieve subscription link content
        links_content = html_content(url_link)
        array_links_content.append(links_content)
        # Separate encoded and unencoded strings
        decoded_contents = decode_string(array_links_content)
    except:
        continue

for content in decoded_contents:
    try:
        # Split each link contents into array and split by lines
        link_contents = content.splitlines()
        link_contents = [element for element in link_contents if element not in ['\n','\t','']]
        # Iterate over link contents to subtract titles
        for index, element in enumerate(link_contents):
            link_contents[index] = re.sub(r"#[^#]+$", "", element)
        array_links_content_decoded.extend(link_contents)
    except:
        continue

# Merge all subscription links content and find all protocols matches base on protocol pattern
content_merged = "\n".join(array_links_content_decoded)
matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality = find_matches(content_merged)


def remove_duplicate(shadow_array, trojan_array, vmess_array, vless_array, reality_array, vmess_decode_dedup = True):
    # Remove duplicate configurations of telegram channels
    shadow_array = list(set(shadow_array))
    trojan_array = list(set(trojan_array))
    vmess_array = list(set(vmess_array))
    vless_array = list(set(vless_array))
    reality_array = list(set(reality_array))

    if vmess_decode_dedup:
        # Decode vmess configs to change title and remove duplicate
        for index, element in enumerate(vmess_array):
            vmess_array[index] = decode_vmess(element)
        vmess_array = [config for config in vmess_array if config != None]
        vmess_array = list(set(vmess_array))

    return shadow_array, trojan_array, vmess_array, vless_array, reality_array


def modify_config(shadow_array, trojan_array, vmess_array, vless_array, reality_array):
    # Checkout connectivity and modify title and protocol type address and resolve IP address
    shadow_array, shadow_tls_array, shadow_non_tls_array, shadow_tcp_array, shadow_ws_array, shadow_http_array, shadow_grpc_array = check_modify_config(array_configuration = shadow_array, protocol_type = "SHADOWSOCKS")
    trojan_array, trojan_tls_array, trojan_non_tls_array, trojan_tcp_array, trojan_ws_array, trojan_http_array, trojan_grpc_array = check_modify_config(array_configuration = trojan_array, protocol_type = "TROJAN")
    vmess_array, vmess_tls_array, vmess_non_tls_array, vmess_tcp_array, vmess_ws_array, vmess_http_array, vmess_grpc_array = check_modify_config(array_configuration = vmess_array, protocol_type = "VMESS")
    vless_array, vless_tls_array, vless_non_tls_array, vless_tcp_array, vless_ws_array, vless_http_array, vless_grpc_array = check_modify_config(array_configuration = vless_array, protocol_type = "VLESS")
    reality_array, reality_tls_array, reality_non_tls_array, reality_tcp_array, reality_ws_array, reality_http_array, reality_grpc_array = check_modify_config(array_configuration = reality_array, protocol_type = "REALITY")

    # Initialize security and netowrk array
    tls_array = list()
    non_tls_array = list()

    tcp_array = list()
    ws_array = list()
    http_array = list()
    grpc_array = list()

    for array in [shadow_tls_array, trojan_tls_array, vmess_tls_array, vless_tls_array, reality_tls_array]:
        tls_array.extend(array)
    for array in [shadow_non_tls_array, trojan_non_tls_array, vmess_non_tls_array, vless_non_tls_array, reality_non_tls_array]:
        non_tls_array.extend(array)

    for array in [shadow_tcp_array, trojan_tcp_array, vmess_tcp_array, vless_tcp_array, reality_tcp_array]:
        tcp_array.extend(array)
    for array in [shadow_ws_array, trojan_ws_array, vmess_ws_array, vless_ws_array, reality_ws_array]:
        ws_array.extend(array)
    for array in [shadow_http_array, trojan_http_array, vmess_http_array, vless_http_array, reality_http_array]:
        http_array.extend(array)
    for array in [shadow_grpc_array, trojan_grpc_array, vmess_grpc_array, vless_grpc_array, reality_grpc_array]:
        grpc_array.extend(array)

    return shadow_array, trojan_array, vmess_array, vless_array, reality_array, tls_array, non_tls_array, tcp_array, ws_array, http_array, grpc_array


# Remove duplicate configurations of telegram channels and subscription links contents
array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality = remove_duplicate(array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality)
matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality = remove_duplicate(matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality)

# Checkout connectivity and modify title and protocol type address and resolve IP address
array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, array_tls, array_non_tls, array_tcp, array_ws, array_http, array_grpc = modify_config(array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality)
matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, matches_tls, matches_non_tls, matches_tcp, matches_ws, matches_http, matches_grpc = modify_config(matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality)


# Extend subscription links contents to telegram channel contents
array_shadowsocks.extend(matches_shadowsocks)
array_trojan.extend(matches_trojan)
array_vmess.extend(matches_vmess)
array_vless.extend(matches_vless)
array_reality.extend(matches_reality)

# Remove duplicate configurations after modifying telegram channels and subscription links contents
array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality = remove_duplicate(array_shadowsocks, array_trojan, array_vmess, array_vless, array_reality, vmess_decode_dedup = False)
matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality = remove_duplicate(matches_shadowsocks, matches_trojan, matches_vmess, matches_vless, matches_reality, vmess_decode_dedup = False)

# Extend subscription links contents to telegram channel contents
array_tls.extend(matches_tls)
array_non_tls.extend(matches_non_tls)
array_tcp.extend(matches_tcp)
array_ws.extend(matches_ws)
array_http.extend(matches_http)
array_grpc.extend(matches_grpc)

# Remove duplicate configurations after modifying telegram channels and subscription links contents
array_tls = list(set(array_tls))
array_non_tls = list(set(array_non_tls))
array_tcp = list(set(array_tcp))
array_ws = list(set(array_ws))
array_http = list(set(array_http))
array_grpc = list(set(array_grpc))


# Combine all configurations into one mixed configuration array and shuffle
array_mixed = array_shadowsocks + array_trojan + array_vmess + array_vless + array_reality
random.shuffle(array_mixed)

# Define chunk size for splitted arrays
chunk_size = math.ceil(len(array_mixed)/10)
chunks = list()

# Split and get chunks of mixed configurations array 
for i in range(0, len(array_mixed), chunk_size):
    chunk = array_mixed[i : i + chunk_size]
    chunks.append(chunk)


# Define update date and time based on Iran timezone and calendar
datetime_update = jdatetime.datetime.now(tz = timezone(timedelta(hours = 3, minutes = 30)))
datetime_update_str = datetime_update.strftime("\U0001F504 LATEST-UPDATE \U0001F4C5 %a-%d-%b-%Y \U0001F551 %H:%M").upper()

# Define update time based on protocol type
re_int = f"vless://abcabca-abcd-abcd-abcd-abcabcabcabc@127.0.0.1:1080?security=tls&type=tcp#{datetime_update_str}"
vl_int = f"vless://abcabca-abcd-abcd-abcd-abcabcabcabc@127.0.0.1:1080?security=tls&type=tcp#{datetime_update_str}"
vm_int = {"add":"127.0.0.1","aid":"0","host":"","id":"abcabca-abcd-abcd-abcd-abcabcabcabc","net":"tcp","path":"",
          "port":"1080","ps":f"{datetime_update_str}","scy":"auto","sni":"","tls":"","type":"","v":"2"}
vm_int = json.dumps(vm_int)
vm_int = vm_int.encode('utf-8')
vm_int = base64.b64encode(vm_int).decode('utf-8')
vm_int = f'vmess://{vm_int}'
tr_int = f"trojan://abcabca-abcd-abcd-abcd-abcabcabcabc@127.0.0.1:1080?security=tls&type=tcp#{datetime_update_str}"
ss_int = f"ss://bm9uZTphYmNhYmNhLWFiY2QtYWJjZC1hYmNkLWFiY2FiY2FiY2FiYw==@127.0.0.1:1080#{datetime_update_str}"

# Define develooper sign
dev_sign = "\U0001F468\U0001F3FB\u200D\U0001F4BB SOROUSH-MIRZAEI \U0001F4CC CNTCT-FLLW-SYDSRSMRZ"

# Define develooper based on protocol type
re_lst = f"vless://acbacba-dcba-dcba-dcba-cbacbacbacba@127.0.0.1:8080?security=tls&type=tcp#{dev_sign}"
vl_lst = f"vless://acbacba-dcba-dcba-dcba-cbacbacbacba@127.0.0.1:8080?security=tls&type=tcp#{dev_sign}"
vm_lst = {"add":"127.0.0.1","aid":"0","host":"","id":"acbacba-dcba-dcba-dcba-cbacbacbacba","net":"tcp","path":"",
          "port":"8080","ps":f"{dev_sign}","scy":"auto","sni":"","tls":"","type":"","v":"2"}
vm_lst = json.dumps(vm_lst)
vm_lst = vm_lst.encode('utf-8')
vm_lst = base64.b64encode(vm_lst).decode('utf-8')
vm_lst = f'vmess://{vm_lst}'
tr_lst = f"trojan://acbacba-dcba-dcba-dcba-cbacbacbacba@127.0.0.1:8080?security=tls&type=tcp#{dev_sign}"
ss_lst = f"ss://bm9uZTphY2JhY2JhLWRjYmEtZGNiYS1kY2JhLWNiYWNiYWNiYWNiYQ==@127.0.0.1:8080#{dev_sign}"


# Save configurations based on splitted and chunks
for i in range(0, 10):
    if i < len(chunks):
        with open(f"./splitted/mixed-{i}", "w", encoding="utf-8") as file:
            chunks[i].insert(0, tr_int)
            chunks[i].append(tr_lst)
            file.write(base64.b64encode("\n".join(chunks[i]).encode("utf-8")).decode("utf-8"))
    else:
        with open(f"./splitted/mixed-{i}", "w", encoding="utf-8") as file:
            file.write("")


# Save all mixed array and subscription links content
with open("./splitted/mixed", "w", encoding="utf-8") as file:
    array_mixed.insert(0, tr_int)
    array_mixed.append(tr_lst)
    file.write(base64.b64encode("\n".join(array_mixed).encode("utf-8")).decode("utf-8"))


# Decode vmess configs to change title and remove duplicate
all_subscription_matches = matches_shadowsocks + matches_trojan + matches_vmess + matches_vless + matches_reality
all_subscription_matches = list(set(all_subscription_matches))

with open("./splitted/subscribe", "w", encoding="utf-8") as file:
    all_subscription_matches.insert(0, tr_int)
    all_subscription_matches.append(tr_lst)
    file.write(base64.b64encode("\n".join(all_subscription_matches).encode("utf-8")).decode("utf-8"))


# Adds update time into protocol type lists
array_shadowsocks.insert(0, ss_int)
array_trojan.insert(0, tr_int)
array_vmess.insert(0, vm_int)
array_vless.insert(0, vl_int)
array_reality.insert(0, re_int)

# Adds develooper sign into protocol type lists
array_shadowsocks.append(ss_lst)
array_trojan.append(tr_lst)
array_vmess.append(vm_lst)
array_vless.append(vl_lst)
array_reality.append(re_lst)

# Save configurations into files splitted based on configuration type
with open("./protocols/shadowsocks", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_shadowsocks).encode("utf-8")).decode("utf-8"))
with open("./protocols/trojan", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_trojan).encode("utf-8")).decode("utf-8"))
with open("./protocols/vmess", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_vmess).encode("utf-8")).decode("utf-8"))
with open("./protocols/vless", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_vless).encode("utf-8")).decode("utf-8"))
with open("./protocols/reality", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_reality).encode("utf-8")).decode("utf-8"))


# Adds update time into protocol type lists
array_tls.insert(0, vl_int)
array_non_tls.insert(0, vl_int)
array_tcp.insert(0, vl_int)
array_ws.insert(0, vl_int)
array_http.insert(0, vl_int)
array_grpc.insert(0, vl_int)

array_tls.append(vl_lst)
array_non_tls.append(vl_lst)
array_tcp.append(vl_lst)
array_ws.append(vl_lst)
array_http.append(vl_lst)
array_grpc.append(vl_lst)

# Save configurations into files splitted based on configuration type
with open("./security/tls", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_tls).encode("utf-8")).decode("utf-8"))
with open("./security/non-tls", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_non_tls).encode("utf-8")).decode("utf-8"))
with open("./networks/tcp", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_tcp).encode("utf-8")).decode("utf-8"))
with open("./networks/ws", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_ws).encode("utf-8")).decode("utf-8"))
with open("./networks/http", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_http).encode("utf-8")).decode("utf-8"))
with open("./networks/grpc", "w", encoding="utf-8") as file:
    file.write(base64.b64encode("\n".join(array_grpc).encode("utf-8")).decode("utf-8"))
