#!/usr/bin/env python3
"""
Business Email Validator - Desktop GUI
Wraps the existing email validation logic in a modern tkinter interface.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading, sys, time, re, os, queue, random, datetime, collections

try:
	import psutil, requests, IP2Location, dns.resolver, dns.reversename, dns.exception
except ImportError:
	if os.name == 'nt':
		os.system(f'"{sys.executable}" -m pip install psutil requests dnspython IP2Location')
	else:
		os.system('apt -y install python3-pip; pip3 install psutil requests dnspython IP2Location')
	import psutil, requests, IP2Location, dns.resolver, dns.reversename, dns.exception

# ═══════════════════════════════════════════════════════════════
# CONSTANTS — identical to get_safe_mails.py
# ═══════════════════════════════════════════════════════════════

custom_dns_nameservers = '1.1.1.2,1.0.0.2,208.67.222.222,208.67.220.220,1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9,149.112.112.112,185.228.168.9,185.228.169.9,76.76.19.19,76.223.122.150,94.140.14.14,94.140.15.15,84.200.69.80,84.200.70.40,8.26.56.26,8.20.247.20,205.171.3.65,205.171.2.65,195.46.39.39,195.46.39.40,159.89.120.99,134.195.4.2,216.146.35.35,216.146.36.36,45.33.97.5,37.235.1.177,77.88.8.8,77.88.8.1,91.239.100.100,89.233.43.71,80.80.80.80,80.80.81.81,74.82.42.42,,64.6.64.6,64.6.65.6,45.77.165.194,45.32.36.36'.split(',')
dns_trusted_url = 'https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt'
ip2location_url = 'https://github.com/aels/mailtools/releases/download/ip2location/ip2location.bin'
ip2location_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ip2location.bin')
whitelisted_mx  = r'(google\.com|outlook\.com|googlemail\.com|qq\.com|improvmx\.com|registrar-servers\.com|emailsrvr\.com|secureserver\.net|yandex\.net|amazonaws\.com|zoho\.com|messagingengine\.com|mailgun\.org|netease\.com|yandex\.ru|ovh\.net|gandi\.net|zoho\.eu|mxhichina\.com|mail\.ru|sbnation\.com|beget\.com|securemx\.jp|hostedemail\.com|arsmtp\.com|yahoodns\.net|protonmail\.ch|pair\.com|ne\.jp|1and1\.com|ispgateway\.de|dreamhost\.com|amazon\.com|dfn\.de|aliyun\.com|163\.com|mailanyone\.net|suremail\.cn|privateemail\.com|one\.com|espmailservice\.net|nic\.in|kasserver\.com|oxcs\.net|everyone\.net|above\.com|timeweb\.ru|serverdata\.net|forwardemail\.net|bund\.de|mailhostbox\.com|kundenserver\.de|ionos\.com|expedia\.com|icoremail\.net|hostedmxserver\.com|263xmail\.com|infomaniak\.ch|hostinger\.com|automattic\.com|alibaba-inc\.com|feishu\.cn|cnhi\.com|h-email\.net|zohomail\.com|outlook\.cn|easydns\.com|cscdns\.net|zoho\.in|name\.com|migadu\.com|mailbox\.org|untd\.com|stackmail\.com|kagoya\.net|forwardmx\.io|carrierzone\.com|ucoz\.net|renr\.es|redhat\.com|hotmail\.com|hostinger\.in|fusemail\.net|disney\.com|bell\.ca)$'
dangerous_users = r'^hr$|about|abuse|admin|apps|calendar|catch|community|confirm|contracts|customer|daemon|director|excel|fax|feedback|found|hello|help|home|invite|job|mail|manager|marketing|newsletter|office|orders|postmaster|regist|reply|report|sales|scanner|security|service|staff|submission|survey|tech|test|twitter|verification|webmaster'
dangerous_zones = r'\.(gov|mil|edu)(\.[a-z.]+|$)'
dangerous_isps  = r'acronis|acros|adlice|alinto|appriver|aspav|atomdata|avanan|avast|barracuda|baseq|bitdefender|broadcom|btitalia|censornet|checkpoint|cisco|cistymail|clean-mailbox|clearswift|closedport|cloudflare|comforte|corvid|crsp|cyren|darktrace|data-mail-group|dmarcly|drweb|duocircle|e-purifier|earthlink-vadesecure|ecsc|eicar|elivescanned|emailsorting|eset|essentials|exchangedefender|fireeye|forcepoint|fortinet|gartner|gatefy|gonkar|group-ib|guard|helpsystems|heluna|hosted-247|iberlayer|indevis|infowatch|intermedia|intra2net|invalid|ioactive|ironscales|isync|itserver|jellyfish|kcsfa.co|keycaptcha|krvtz|libraesva|link11|localhost|logix|mailborder.co|mailchannels|mailcleaner|mailcontrol|mailinator|mailroute|mailsift|mailstrainer|mcafee|mdaemon|mx-relay|mx1.ik2|mx37\.m..p\.com|mxcomet|mxgate|mxstorm|n-able|n2net|nano-av|netintelligence|network-box|networkboxusa|newnettechnologies|newtonit.co|odysseycs|openwall|opswat|perfectmail|perimeterwatch|plesk|prodaft|proofpoint|proxmox|redcondor|reflexion|retarus|safedns|safeweb|sec-provider|secureage|securence|security|sendio|shield|sicontact|smxemail|sonicwall|sophos|spamtitan|spfbl|spiceworks|stopsign|supercleanmail|techtarget|titanhq|trellix|trendmicro|trustifi|trustwave|tryton|uni-muenster|usergate|vadesecure|wessexnetworks|zillya|zyxel'
dangerous_isps2 = r'abus|bad|black|bot|brukalai|excello|filter|honey|junk|lab|list|metunet|rbl|research|security|spam|trap|ubl|virtual|virus|vm\d'
disposable_domains = r'mailinator\.com|guerrillamail\.com|tempmail\.com|throwam\.com|yopmail\.com|sharklasers\.com|disposable\.com|10minutemail\.com|getairmail\.com'
consumer_domains = {
	'gmail.com', 'googlemail.com',
	'outlook.com', 'hotmail.com', 'hotmail.co.uk', 'hotmail.fr',
	'live.com', 'live.co.uk', 'msn.com', 'passport.com',
	'yahoo.com', 'yahoo.co.uk', 'yahoo.fr', 'yahoo.es',
	'yahoo.de', 'yahoo.it', 'yahoo.com.br', 'yahoo.co.jp', 'ymail.com',
	'yandex.com', 'yandex.ru', 'ya.ru',
	'icloud.com', 'me.com', 'mac.com',
	'aol.com', 'aim.com',
	'protonmail.com', 'proton.me', 'pm.me',
	'zoho.com', 'zohomail.com',
	'mail.com', 'email.com', 'gmx.com', 'gmx.net',
	'imap.com', 'inbox.com', 'fastmail.com', 'hushmail.com',
	'tutanota.com', 'tutamail.com', 'rediffmail.com',
}

nameserver_failures = collections.Counter()

resolver_obj = dns.resolver.Resolver()
resolver_obj.rotate = True
resolver_obj.timeout = 2
resolver_obj.lifetime = 2
resolver_obj.cache = dns.resolver.LRUCache()
requests.packages.urllib3.disable_warnings()

# ═══════════════════════════════════════════════════════════════
# VALIDATION FUNCTIONS — identical logic to get_safe_mails.py
# ═══════════════════════════════════════════════════════════════

def first(a):
	return (a or [''])[0]

def switch_dns_nameserver():
	global resolver_obj, custom_dns_nameservers, nameserver_failures
	try:
		current_ns = resolver_obj.nameservers[0]
		nameserver_failures[current_ns] += 1
	except: pass
	healthy = [ns for ns in custom_dns_nameservers if nameserver_failures[ns] < 3]
	pool = healthy if healthy else custom_dns_nameservers
	resolver_obj.nameservers = [random.choice(pool)]
	resolver_obj.rotate = True
	return True

def get_ns_record(name, string, retries=3):
	global resolver_obj
	last_exception = None
	for attempt in range(retries):
		try:
			if name == 'a':
				try: string = resolver_obj.resolve(string, 'cname')[0].target
				except: pass
				return resolver_obj.resolve(string, 'a')[0].to_text()
			if name == 'ptr':
				return str(resolver_obj.resolve(dns.reversename.from_address(string), 'ptr')[0])[:-1]
			if name == 'mx':
				return str(resolver_obj.resolve(string, 'mx')[0].exchange)[:-1]
			if name == 'txt':
				return [str(txt) for txt in resolver_obj.resolve(string, 'txt')]
		except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
			raise e
		except Exception as e:
			last_exception = e
			reason = str(e)
			is_transient = any([
				isinstance(e, (dns.exception.Timeout, dns.resolver.NoNameservers, ConnectionRefusedError, OSError)),
				'solution lifetime expired' in reason,
				'SERVFAIL' in reason
			])
			if is_transient:
				switch_dns_nameserver()
				if attempt < retries - 1:
					time.sleep(0.5)
					continue
			raise e
	if last_exception: raise last_exception
	return ''

def is_valid_syntax(email):
	if len(email) > 254: return False, 'email too long (>254)'
	parts = email.split('@')
	if len(parts) != 2: return False, 'invalid format: multiple or missing @'
	user, host = parts
	if not user or not host: return False, 'invalid format'
	if len(user) > 64: return False, 'local part too long (>64)'
	if '..' in user or user.startswith('.') or user.endswith('.'): return False, 'invalid dots in local part'
	if not re.match(r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+$', user): return False, 'invalid chars in local part'
	if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', host): return False, 'invalid domain format'
	tld = host.split('.')[-1]
	if len(tld) < 2 or tld.isdigit(): return False, 'invalid TLD'
	if host.lower() in consumer_domains: return False, 'consumer email domain: ' + host
	if re.search(disposable_domains, host.lower()): return False, 'disposable email domain'
	return True, ''

def get_provider(mx_record):
	mx_record = mx_record.lower()
	if any(p in mx_record for p in ['outlook.com', 'hotmail.com', 'microsoft.com', 'protection.outlook.com']):
		return 'microsoft'
	if any(p in mx_record for p in ['google.com', 'googlemail.com', 'aspmx.l.google.com']):
		return 'google'
	if any(p in mx_record for p in ['yahoodns.net', 'yahoo.com', 'yahoomail.com']):
		return 'yahoo'
	return 'others'

def is_safe_host(email, goods_cache, bads_cache, database, selected_email_providers):
	user, host = email.split('@')
	valid, reason = is_valid_syntax(email)
	if not valid: raise Exception(reason)
	if host in bads_cache: raise Exception(bads_cache[host])
	if host in goods_cache: return goods_cache[host]
	if re.search(dangerous_zones, host.lower()): raise Exception('bad zone: '+host)
	email_mx = get_ns_record('mx', host).lower()
	if not email_mx: raise Exception('no <mx> records found for: '+host)
	if selected_email_providers:
		for domain in selected_email_providers.split(','):
			if domain and domain in host: return email_mx
	if selected_email_providers:
		for domain in selected_email_providers.split(','):
			if domain and domain in email_mx: return email_mx
		raise Exception(email_mx)
	if re.search(whitelisted_mx, email_mx): return email_mx
	if re.search(dangerous_isps+r'|'+dangerous_isps2, email_mx): raise Exception(email_mx)
	email_mx_ip = get_ns_record('a', email_mx)
	if not email_mx_ip: raise Exception('no <a> record found for mx server: '+email_mx)
	email_isp = database.get_isp(email_mx_ip) or ''
	if re.search(dangerous_isps+r'|'+dangerous_isps2, email_isp.lower()): raise Exception(email_isp)
	reversename = get_ns_record('ptr', email_mx_ip).lower()
	if re.search(dangerous_isps2, reversename): raise Exception(reversename)
	return email_mx

def is_safe_username(email):
	user, host = email.split('@')
	if re.search(dangerous_users, user.lower()): raise Exception('bad username: '+user)
	return email

def is_safe_email(email, goods_cache, bads_cache, database, selected_email_providers):
	host = email.split('@')[-1]
	try:
		is_good_host = is_safe_host(email, goods_cache, bads_cache, database, selected_email_providers)
		goods_cache[host] = is_good_host
		is_safe_username(email)
		return is_good_host
	except Exception as e:
		if 'bad username' not in str(e):
			bads_cache[host] = str(e)
		raise Exception(str(e))

def extract_email(line):
	return first(re.search(r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}', line))

def load_dns_servers():
	global custom_dns_nameservers, dns_trusted_url
	try:
		r = requests.get(dns_trusted_url, timeout=5)
		if r.status_code == 200:
			ips = [ip.strip() for ip in r.text.splitlines() if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip.strip())]
			if ips: custom_dns_nameservers = list(set(ips))
	except: pass

def sec_to_min(i):
	return '%02d:%02d'%(int(i/60), i%60)

# ═══════════════════════════════════════════════════════════════
# GUI THEME CONSTANTS
# ═══════════════════════════════════════════════════════════════

BG_DARK     = '#1e1e1e'
BG_CARD     = '#2d2d2d'
BG_INPUT    = '#3a3a3a'
FG_WHITE    = '#ffffff'
FG_DIM      = '#888888'
GREEN       = '#00c853'
RED         = '#ff1744'
YELLOW      = '#ffd600'
ACCENT_BLUE = '#448aff'
FONT_MONO   = ('Consolas', 10)
FONT_UI     = ('Segoe UI', 10)
FONT_TITLE  = ('Segoe UI', 18, 'bold')
FONT_SUB    = ('Segoe UI', 10)
FONT_STAT   = ('Consolas', 11, 'bold')

# ═══════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════

class EmailValidatorApp:
	def __init__(self, root):
		self.root = root
		self.root.title('Business Email Validator')
		self.root.configure(bg=BG_DARK)
		self.root.minsize(900, 600)
		self.root.geometry('1000x650')

		# State
		self.file_path = tk.StringVar(value='')
		self.providers_var = tk.StringVar(value='')
		self.is_running = False
		self.stop_requested = False
		self.results_path = ''
		self.time_start = 0
		self.log_line_count = 0

		# Validation state (passed to workers)
		self.goods_cache = {}
		self.bads_cache = {}
		self.database = None
		self.ui_queue = queue.Queue()
		self.stats = {
			'total': 0, 'microsoft': 0, 'google': 0, 'yahoo': 0,
			'others': 0, 'dangerous': 0, 'retry': 0,
			'domains': collections.defaultdict(lambda: collections.Counter()),
			'reasons': collections.Counter()
		}
		self.stats_lock = threading.Lock()

		self._build_ui()
		self._init_engine()

	# ─── Engine Init ───────────────────────────────────────────
	def _init_engine(self):
		"""Load DNS servers and IP2Location database at startup."""
		def _init():
			load_dns_servers()
			if not os.path.isfile(ip2location_path):
				self.ui_queue.put(('log_system', 'Downloading ip2location.bin... this may take a moment.'))
				try:
					body = requests.get(ip2location_url, timeout=30).content
					open(ip2location_path, 'wb').write(body)
				except Exception as e:
					self.ui_queue.put(('log_system', f'ERROR: Could not download ip2location.bin: {e}'))
					return
			try:
				self.database = IP2Location.IP2Location(ip2location_path, 'SHARED_MEMORY')
			except Exception as e:
				self.ui_queue.put(('log_system', f'ERROR loading IP2Location: {e}'))
				return
			ns_count = len(custom_dns_nameservers)
			self.ui_queue.put(('log_system', f'Engine ready. DNS pool: {ns_count:,} nameservers.'))
		threading.Thread(target=_init, daemon=True).start()
		self._poll_ui_queue()

	# ─── UI Construction ───────────────────────────────────────
	def _build_ui(self):
		# ── Title Bar ──
		title_frame = tk.Frame(self.root, bg=BG_DARK, pady=12)
		title_frame.pack(fill='x', padx=20)
		tk.Label(title_frame, text='Business Email Validator', font=FONT_TITLE,
				 bg=BG_DARK, fg=FG_WHITE).pack(anchor='w')
		tk.Label(title_frame, text='Validates and sorts business emails effectively at blazing speed.',
				 font=FONT_SUB, bg=BG_DARK, fg=FG_DIM).pack(anchor='w')

		# ── Controls Card ──
		ctrl = tk.Frame(self.root, bg=BG_CARD, pady=14, padx=16,
						highlightbackground='#444', highlightthickness=1)
		ctrl.pack(fill='x', padx=20, pady=(0, 8))

		# Row 1: File picker
		row1 = tk.Frame(ctrl, bg=BG_CARD)
		row1.pack(fill='x', pady=(0, 8))
		self.btn_file = tk.Button(row1, text='📁  Select Email File', command=self._pick_file,
								  bg=ACCENT_BLUE, fg=FG_WHITE, font=FONT_UI, relief='flat',
								  padx=14, pady=4, cursor='hand2', activebackground='#5c9aff')
		self.btn_file.pack(side='left')
		self.lbl_file = tk.Label(row1, textvariable=self.file_path, bg=BG_CARD, fg=FG_DIM,
								font=FONT_UI, anchor='w')
		self.lbl_file.pack(side='left', padx=(12, 0), fill='x', expand=True)

		# Row 2: Providers input
		# row2 = tk.Frame(ctrl, bg=BG_CARD)
		# row2.pack(fill='x', pady=(0, 10))
		# tk.Label(row2, text='Target Providers:', bg=BG_CARD, fg=FG_DIM, font=FONT_UI).pack(side='left')
		# self.ent_providers = tk.Entry(row2, textvariable=self.providers_var, bg=BG_INPUT, fg=FG_WHITE,
		# 							  font=FONT_UI, relief='flat', insertbackground=FG_WHITE)
		# self.ent_providers.pack(side='left', padx=(8, 0), fill='x', expand=True, ipady=4)
		# self.ent_providers.insert(0, '')
		# # Placeholder
		# self.ent_providers.bind('<FocusIn>', lambda e: self._clear_placeholder())
		# self.ent_providers.bind('<FocusOut>', lambda e: self._set_placeholder())
		# self._set_placeholder()

		# Row 3: Buttons + Progress
		row3 = tk.Frame(ctrl, bg=BG_CARD)
		row3.pack(fill='x')
		self.btn_start = tk.Button(row3, text='▶  START', command=self._start, bg=GREEN, fg='#000',
								   font=('Segoe UI', 11, 'bold'), relief='flat', padx=24, pady=6,
								   cursor='hand2', activebackground='#00e676')
		self.btn_start.pack(side='left')
		self.btn_stop = tk.Button(row3, text='■  STOP', command=self._stop, bg=RED, fg=FG_WHITE,
								  font=('Segoe UI', 11, 'bold'), relief='flat', padx=24, pady=6,
								  cursor='hand2', state='disabled', activebackground='#ff5252')
		self.btn_stop.pack(side='left', padx=(10, 0))
		self.btn_clear = tk.Button(row3, text='Clear Log', command=self._clear_log,
								   bg=BG_INPUT, fg=FG_DIM, font=FONT_UI, relief='flat',
								   padx=12, pady=4, cursor='hand2')
		self.btn_clear.pack(side='right')

		# Progress bar
		style = ttk.Style()
		style.theme_use('default')
		style.configure('green.Horizontal.TProgressbar', troughcolor=BG_INPUT,
						background=GREEN, thickness=8)
		self.progress = ttk.Progressbar(ctrl, style='green.Horizontal.TProgressbar',
										maximum=100, value=0)
		self.progress.pack(fill='x', pady=(10, 0))

		# ── Log Window ──
		log_frame = tk.Frame(self.root, bg=BG_DARK)
		log_frame.pack(fill='both', expand=True, padx=20, pady=(0, 8))

		self.log = tk.Text(log_frame, bg='#121212', fg=FG_WHITE, font=FONT_MONO,
						   relief='flat', wrap='none', state='disabled',
						   insertbackground=FG_WHITE, selectbackground='#444',
						   padx=10, pady=8, spacing1=2)
		scrollbar = tk.Scrollbar(log_frame, command=self.log.yview, bg=BG_DARK,
								 troughcolor=BG_DARK)
		self.log.configure(yscrollcommand=scrollbar.set)
		scrollbar.pack(side='right', fill='y')
		self.log.pack(side='left', fill='both', expand=True)

		# Configure log tags
		self.log.tag_configure('valid', foreground=GREEN)
		self.log.tag_configure('invalid', foreground=RED)
		self.log.tag_configure('processing', foreground=YELLOW)
		self.log.tag_configure('system', foreground=ACCENT_BLUE)

		# ── Stats Bar ──
		stats_frame = tk.Frame(self.root, bg=BG_CARD, pady=10, padx=16,
							   highlightbackground='#444', highlightthickness=1)
		stats_frame.pack(fill='x', padx=20, pady=(0, 12))

		self.stat_labels = {}
		stat_items = [
			('microsoft', 'Microsoft'), ('google', 'Google'), ('yahoo', 'Yahoo'),
			('others', 'Others'), ('dangerous', 'Dangerous'), ('retry', 'Retry')
		]
		for key, label in stat_items:
			f = tk.Frame(stats_frame, bg=BG_CARD)
			f.pack(side='left', padx=(0, 18))
			tk.Label(f, text=label+':', bg=BG_CARD, fg=FG_DIM, font=FONT_UI).pack(side='left')
			lbl = tk.Label(f, text='0', bg=BG_CARD, fg=FG_WHITE, font=FONT_STAT)
			lbl.pack(side='left', padx=(4, 0))
			self.stat_labels[key] = lbl

		# Speed + Time on right
		right_stats = tk.Frame(stats_frame, bg=BG_CARD)
		right_stats.pack(side='right')
		self.lbl_speed = tk.Label(right_stats, text='0 emails/sec', bg=BG_CARD, fg=GREEN, font=FONT_STAT)
		self.lbl_speed.pack(side='left', padx=(0, 16))
		self.lbl_time = tk.Label(right_stats, text='00:00', bg=BG_CARD, fg=FG_DIM, font=FONT_STAT)
		self.lbl_time.pack(side='left')

	# ─── Placeholder Helpers ───────────────────────────────────
	def _set_placeholder(self):
		if not self.providers_var.get():
			self.ent_providers.insert(0, 'e.g. google,microsoft - leave empty for all')
			self.ent_providers.config(fg=FG_DIM)

	def _clear_placeholder(self):
		if self.ent_providers.get() == 'e.g. google,microsoft - leave empty for all':
			self.ent_providers.delete(0, 'end')
			self.ent_providers.config(fg=FG_WHITE)

	# ─── File Picker ───────────────────────────────────────────
	def _pick_file(self):
		path = filedialog.askopenfilename(
			title='Select Email File',
			filetypes=[('Text Files', '*.txt'), ('CSV Files', '*.csv'), ('All Files', '*.*')]
		)
		if path:
			self.file_path.set(path)

	# ─── Log Helpers ───────────────────────────────────────────
	def _log(self, text, tag='system'):
		self.log.configure(state='normal')
		self.log.insert('end', text + '\n', tag)
		self.log_line_count += 1
		# Trim old lines if log gets too long
		if self.log_line_count > 1000:
			self.log.delete('1.0', '201.0')
			self.log_line_count -= 200
		self.log.see('end')
		self.log.configure(state='disabled')

	def _clear_log(self):
		self.log.configure(state='normal')
		self.log.delete('1.0', 'end')
		self.log_line_count = 0
		self.log.configure(state='disabled')

	# ─── UI Queue Polling ──────────────────────────────────────
	def _poll_ui_queue(self):
		try:
			while True:
				msg = self.ui_queue.get_nowait()
				action = msg[0]
				if action == 'log_valid':
					email, category = msg[1], msg[2]
					self._log(f'  ✓  {email}  →  {category}', 'valid')
				elif action == 'log_invalid':
					email, reason = msg[1], msg[2]
					self._log(f'  ✗  {email}  →  {reason}', 'invalid')
				elif action == 'log_system':
					self._log(f'  ℹ  {msg[1]}', 'system')
				elif action == 'update_stats':
					self._refresh_stats()
				elif action == 'done':
					self._on_done(msg[1])
		except queue.Empty:
			pass
		self.root.after(100, self._poll_ui_queue)

	def _refresh_stats(self):
		with self.stats_lock:
			for key in ['microsoft', 'google', 'yahoo', 'others', 'dangerous', 'retry']:
				self.stat_labels[key].config(text=f'{self.stats[key]:,}')
			total = self.stats['total']

		if self.time_start > 0:
			elapsed = time.time() - self.time_start
			speed = total / elapsed if elapsed > 0 else 0
			self.lbl_speed.config(text=f'{speed:.1f} emails/sec')
			self.lbl_time.config(text=sec_to_min(elapsed))

		if hasattr(self, 'total_lines') and self.total_lines > 0:
			pct = min(100, total / self.total_lines * 100)
			self.progress['value'] = pct

	def _on_done(self, report_path):
		self.is_running = False
		self.btn_start.config(state='normal')
		self.btn_stop.config(state='disabled')
		self.progress['value'] = 100
		self._refresh_stats()

		result = messagebox.askquestion(
			'Validation Complete',
			f'Done! Report saved to:\n{report_path}\n\nOpen results folder?',
			icon='info'
		)
		if result == 'yes':
			if os.name == 'nt':
				os.startfile(os.path.dirname(report_path))
			else:
				import subprocess
				subprocess.Popen(['xdg-open', os.path.dirname(report_path)])

	# ─── Start / Stop ──────────────────────────────────────────
	def _start(self):
		fpath = self.file_path.get()
		if not fpath or not os.path.isfile(fpath):
			messagebox.showerror('Error', 'Please select a valid email file.')
			return
		if self.database is None:
			messagebox.showerror('Error', 'Engine not ready. IP2Location database not loaded.')
			return

		# Reset state
		self.stop_requested = False
		self.is_running = True
		self.goods_cache = {}
		self.bads_cache = {}
		self.time_start = time.time()
		with self.stats_lock:
			self.stats = {
				'total': 0, 'microsoft': 0, 'google': 0, 'yahoo': 0,
				'others': 0, 'dangerous': 0, 'retry': 0,
				'domains': collections.defaultdict(lambda: collections.Counter()),
				'reasons': collections.Counter()
			}
		self._refresh_stats()
		self.progress['value'] = 0

		providers_text = self.providers_var.get()
		if providers_text == 'e.g. google,microsoft - leave empty for all':
			providers_text = ''

		# Results folder and timestamp
		self.results_path = os.path.join(os.path.dirname(os.path.abspath(fpath)), 'results')
		self.run_timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
		os.makedirs(self.results_path, exist_ok=True)

		self.btn_start.config(state='disabled')
		self.btn_stop.config(state='normal')

		self._log(f'Starting validation: {os.path.basename(fpath)}', 'system')

		threading.Thread(target=self._run_validation,
						 args=(fpath, providers_text), daemon=True).start()

	def _stop(self):
		self.stop_requested = True
		self.ui_queue.put(('log_system', 'Stopping... generating report for completed work.'))

	# ─── Validation Runner ─────────────────────────────────────
	def _run_validation(self, file_path, selected_providers):
		try:
			with open(file_path, 'r', encoding='utf-8-sig', errors='ignore') as fp:
				lines = [line.strip() for line in fp if line.strip()]

			# Sort by domain for cache optimization
			def get_domain(line):
				email = extract_email(line)
				return email.split('@')[-1].lower() if email and '@' in email else ''
			lines.sort(key=get_domain)

			self.total_lines = len(lines)
			self.ui_queue.put(('log_system', f'Loaded {self.total_lines:,} lines. Processing...'))

			# Open output files
			handles = {}
			for cat in ['microsoft', 'google', 'yahoo', 'others', 'dangerous', 'retry']:
				cat_dir = os.path.join(self.results_path, cat)
				os.makedirs(cat_dir, exist_ok=True)
				handles[cat] = open(os.path.join(cat_dir, f'{self.run_timestamp}.txt'), 'a', encoding='utf-8')

			# Process with thread pool
			work_queue = queue.Queue()
			result_queue = queue.Queue()
			active_threads = 0
			threads_lock = threading.Lock()
			max_workers = 50

			def worker():
				nonlocal active_threads
				while True:
					try:
						line = work_queue.get(timeout=1)
					except queue.Empty:
						if self.stop_requested:
							break
						continue
					if line is None:
						break

					email = extract_email(line)
					if not email:
						result_queue.put(('skip', line, '', ''))
						continue

					try:
						# IMPORTANT FIX for GUI: Pass an empty dictionary if goods_cache doesn't exist 
						# to prevent dict update errors or timeout blocks.
						mx_record = is_safe_email(email, self.goods_cache, self.bads_cache,
												   self.database, selected_providers)
						provider = get_provider(mx_record)
						result_queue.put(('valid', line, email, provider))
					except Exception as e:
						reason = str(e)
						transient_errors = (dns.exception.Timeout, dns.resolver.NoNameservers,
											requests.exceptions.ConnectionError)
						is_transient = (isinstance(e, transient_errors) or
										'solution lifetime expired' in reason or
										'network unreachable' in reason.lower())
						if is_transient:
							result_queue.put(('retry', line, email, reason))
						else:
							result_queue.put(('invalid', line, email, reason))

				with threads_lock:
					active_threads -= 1

			# Start workers
			for _ in range(min(max_workers, max(1, len(lines)))):
				active_threads += 1
				threading.Thread(target=worker, daemon=True).start()

			# Feed work queue
			for line in lines:
				if self.stop_requested:
					break
				work_queue.put(line)

			# Signal workers to stop
			for _ in range(max_workers):
				work_queue.put(None)

			# Process results
			processed = 0
			while processed < len(lines) and not (active_threads == 0 and result_queue.empty()):
				if self.stop_requested and result_queue.empty():
					break
				try:
					status, line, email, detail = result_queue.get(timeout=0.5)
				except queue.Empty:
					continue

				processed += 1

				if status == 'valid':
					handles[detail].write(line + '\n')
					handles[detail].flush()
					with self.stats_lock:
						self.stats['total'] += 1
						self.stats[detail] += 1
						host = email.split('@')[-1].lower()
						self.stats['domains'][detail][host] += 1
					self.ui_queue.put(('log_valid', email, detail))

				elif status == 'retry':
					handles['retry'].write(line + '\n')
					handles['retry'].flush()
					with self.stats_lock:
						self.stats['total'] += 1
						self.stats['retry'] += 1
					self.ui_queue.put(('log_invalid', email, f'retry: {detail}'))

				elif status == 'invalid':
					handles['dangerous'].write(line + '; ' + detail + '\n')
					handles['dangerous'].flush()
					with self.stats_lock:
						self.stats['total'] += 1
						self.stats['dangerous'] += 1
						self.stats['reasons'][detail] += 1
						host = email.split('@')[-1].lower() if '@' in email else 'unknown'
						self.stats['domains']['dangerous'][host] += 1
					self.ui_queue.put(('log_invalid', email, detail))

				elif status == 'skip':
					with self.stats_lock:
						self.stats['total'] += 1

				self.ui_queue.put(('update_stats',))

			# Close file handles
			for h in handles.values():
				h.close()

			# Generate report
			report_path = self._generate_report()
			self.ui_queue.put(('done', report_path))

		except Exception as e:
			self.ui_queue.put(('log_system', f'ERROR: {e}'))
			self.is_running = False
			# Re-enable buttons via queue
			self.ui_queue.put(('done', ''))

	def _generate_report(self):
		duration = time.time() - self.time_start
		with self.stats_lock:
			avg_speed = self.stats['total'] / duration if duration > 0 else 0
			
			report_dir = os.path.join(self.results_path, 'reports')
			os.makedirs(report_dir, exist_ok=True)
			report_path = os.path.join(report_dir, f'report_{self.run_timestamp}.txt')
			
			with open(report_path, 'w', encoding='utf-8') as f:
				f.write('Business Email Validator - Report\n')
				f.write('=' * 40 + '\n')
				f.write(f'Time Taken: {sec_to_min(duration)} ({duration:.2f}s)\n')
				f.write(f'Average Speed: {avg_speed:.2f} emails/s\n\n')
				f.write('Category Breakdown:\n')
				for cat in ['microsoft', 'google', 'yahoo', 'others', 'dangerous', 'retry']:
					f.write(f'  - {cat.capitalize()}: {self.stats[cat]}\n')
				f.write(f'  Total Processed: {self.stats["total"]}\n\n')
				f.write('Top 10 Domains per Category:\n')
				for cat in ['microsoft', 'google', 'yahoo', 'others', 'dangerous']:
					f.write(f'  [{cat.capitalize()}]\n')
					for domain, count in self.stats['domains'][cat].most_common(10):
						f.write(f'    - {domain}: {count}\n')
					f.write('\n')
				f.write('Top 10 Rejection Reasons:\n')
				for reason, count in self.stats['reasons'].most_common(10):
					f.write(f'  - {reason}: {count}\n')
		return report_path


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
	root = tk.Tk()
	# Set icon if available
	try:
		root.iconbitmap(default='')
	except: pass
	app = EmailValidatorApp(root)
	root.mainloop()
