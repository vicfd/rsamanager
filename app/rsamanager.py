import os, re, stat, subprocess
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from config.inventory import rsa_scope
from config.vars import ansible, default_user, path
from datetime import datetime

class RsaManager:
	def __init__(self):
		self.ansible_maximun_connections = ansible["maximun_connections"]
		self.ansible_pattern_play_recap = ansible["pattern_play_recap"]
		self.ansible_pattern_play_recap_details = ansible["pattern_play_recap_details"]
		self.default_user = default_user
		self.now = datetime.now().strftime('%Y%m%d%H%M%S')
		self.path_app = os.getcwd()
		self.path_ansible_inventory_all = os.path.expanduser(path["ansible_inventory_all"])
		self.path_ansible_inventory_scope = os.path.expanduser(path["ansible_inventory_scope"])
		self.path_ansible_playbook = os.path.expanduser(path["ansible_playbook"])
		self.path_log = os.path.expanduser(path["log"])
		self.path_rsa_vault_archive = os.path.expanduser(path["rsa_vault_archive"])
		self.path_rsa_vault_backup = os.path.expanduser(path["rsa_vault_backup"])
		self.path_rsa_vault_live = os.path.expanduser(path["rsa_vault_live"])
		self.path_rsa_vault_new = os.path.expanduser(path["rsa_vault_new"])
		self.path_ssh_config = os.path.expanduser(path["ssh_config"])
		self.rsa_scope = rsa_scope

		# check that folders exists
		if not os.path.exists(self.path_rsa_vault_archive):
			os.makedirs(self.path_rsa_vault_archive)

		if not os.path.exists(self.path_rsa_vault_backup):
			os.makedirs(self.path_rsa_vault_backup)

		if not os.path.exists(self.path_rsa_vault_live):
			os.makedirs(self.path_rsa_vault_live)

		if not os.path.exists(self.path_rsa_vault_new):
			os.makedirs(self.path_rsa_vault_new)

	def regenerate(self):
		assets = {}

		print("creating rsa key and checking ssh configuration")
		for fqdn in self.rsa_scope[os.uname().nodename]:
			assets[fqdn] = {'rsa_updated': False, 'rsa_check_new': False, 'rsa_old_exists': False, 'rsa_old_deleted': False}
			self._ssh_config_create(fqdn)
			self._rsa_key_create(fqdn)

		print("sending rsa key")
		self._rsa_key_send(assets)
		print("checking rsa key")
		self._rsa_key_check_new(assets)
		print("deleting rsa key")
		self._rsa_key_delete(assets)
		print("reorder keys locally")
		self._rsa_key_reorder(assets)
		print("creating logs")
		self._rsa_regenerate_log(assets)

	# read the list of FQDNs from the inventory file
	def _read_inventory(self, file_path):
		fqdn_list = []
		with open(file_path, 'r') as file:
			for line in file:
				fqdn = line.strip()
				if fqdn:
					fqdn_list.append(fqdn)
		return fqdn_list

	# generate the configuration block for machine <fqdn>
	def _ssh_config_create(self, fqdn):
		config = f"# config to {fqdn}\n\tHost {fqdn}\n\tHostName {fqdn}\n\tUser {self.default_user}\n\tIdentityFile {self.path_rsa_vault_live + "/" + fqdn}"

		# add configuration if it doesn't already exist
		if not self._ssh_config_check_block(config, self.path_ssh_config):
			with open(self.path_ssh_config, 'a') as file:
				file.write(config.strip() + '\n')

	def _rsa_key_create(self, fqdn):
		# Generar clave privada RSA
		rsa_private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=4096,
			backend=default_backend()
		)

		# serialize private key on OpenSSH
		rsa_private_key_ssh = rsa_private_key.private_bytes(
			encoding=serialization.Encoding.PEM,  # Formato OpenSSH para claves privadas
			format=serialization.PrivateFormat.OpenSSH,  # No se puede cambiar el formato aquí
			encryption_algorithm=serialization.NoEncryption()  # Sin passphrase
		)

		# serialize public key on OpenSSH
		rsa_public_key = rsa_private_key.public_key()
		rsa_public_key_ssh = rsa_public_key.public_bytes(
			encoding=serialization.Encoding.OpenSSH,  # Formato OpenSSH para claves públicas
			format=serialization.PublicFormat.OpenSSH
		)

		path_private_key = os.path.join(self.path_rsa_vault_new, fqdn)
		path_public_key = os.path.join(self.path_rsa_vault_new, fqdn + ".pub")

		with open(path_private_key, 'wb') as f:
			f.write(rsa_private_key_ssh)

		# private key permission 600 (read and write)
		os.chmod(path_private_key, stat.S_IRUSR | stat.S_IWUSR)

		with open(path_public_key, 'wb') as f:
			f.write(rsa_public_key_ssh)

	# check if the configuration already exists in the SSH config file
	def _ssh_config_check_block(self, config, config_file_path):
		if os.path.exists(config_file_path):
			with open(config_file_path, 'r') as file:
				content = file.read()
				if config.strip() in content:
					return True
		return False

	def _rsa_key_send(self, assets):
		connections = 0 # current try

		# create ansible inventory with all the assets
		ansible_inventory_scope_content = "[scope]"
		for k, v in assets.items():
			ansible_inventory_scope_content += f"\n{k} rsa_key_file={self.path_rsa_vault_new + "/" + k}.pub"

		with open(self.path_ansible_inventory_scope, 'w') as file:
			file.write(ansible_inventory_scope_content)

		while connections < self.ansible_maximun_connections:
			pending = 0 # pending assets to check
			command = f"ansible-playbook -i {self.path_app + "/" + self.path_ansible_inventory_all} -i {self.path_app + "/" + self.path_ansible_inventory_scope} {self.path_app + "/" + self.path_ansible_playbook}/ssh_key_add.yml"
			result = subprocess.run(command, shell=True, capture_output=True, text=True)

			# searching section
			play_recap_match = re.search(self.ansible_pattern_play_recap, result.stdout)

			if play_recap_match:
				play_recap = play_recap_match.group(0) # get the string from 'PLAY RECAP' until the end of the file
				play_recap_lines = play_recap.splitlines() # split on lines

				if play_recap_lines:
					play_recap_lines.pop(0) # remove first line 'PLAY RECAP'
					play_recap_without_index = "\n".join(play_recap_lines) # array to string to apply pattern
					machines_match = re.findall(self.ansible_pattern_play_recap_details, play_recap_without_index) # array [('name','ok','changed','unreachable', 'failed', 'skipped'. 'rescued'. 'ignored')]

					ansible_inventory_scope_content = "[scope]"
					# index fqdn: 0, ok: 1, changed: 2, unreachable: 3, failed: 4, skipped: 5, rescued: 6, ignored: 7
					for machine in machines_match:
						if int(machine[1]) == 0:
							ansible_inventory_scope_content += f"\n{machine[0]} rsa_key_file={self.path_rsa_vault_new + "/" + machine[0]}.pub"
							pending += 1
						else:
							assets[machine[0]]['rsa_updated'] = True

					with open(self.path_ansible_inventory_scope, 'w') as file:
						file.write(ansible_inventory_scope_content)

					connections = self.ansible_maximun_connections if pending == 0 else connections + 1

		if os.path.exists(self.path_ansible_inventory_scope):
			os.remove(self.path_ansible_inventory_scope)

	def _rsa_key_check_new(self, assets):
		connections = 0 # current try

		# create ansible inventory with all the assets
		ansible_inventory_scope_content = "[scope]"
		for k, v in assets.items():
			if v['rsa_updated']:
				ansible_inventory_scope_content += f"\n{k} ansible_ssh_private_key_file={self.path_rsa_vault_new + "/" + k}"

		with open(self.path_ansible_inventory_scope, 'w') as file:
			file.write(ansible_inventory_scope_content)

		while connections < self.ansible_maximun_connections:
			pending = 0 # pending assets to check
			command = f"ansible-playbook -i {self.path_app + "/" + self.path_ansible_inventory_all} -i {self.path_app + "/" + self.path_ansible_inventory_scope} {self.path_app + "/" + self.path_ansible_playbook}/ssh_key_check_new.yml"
			result = subprocess.run(command, shell=True, capture_output=True, text=True)

			# searching section
			play_recap_match = re.search(self.ansible_pattern_play_recap, result.stdout)

			if play_recap_match:
				play_recap = play_recap_match.group(0) # get the string from 'PLAY RECAP' until the end of the file
				play_recap_lines = play_recap.splitlines() # split on lines

				if play_recap_lines:
					play_recap_lines.pop(0) # remove first line 'PLAY RECAP'
					play_recap_without_index = "\n".join(play_recap_lines) # array to string to apply pattern
					machines_match = re.findall(self.ansible_pattern_play_recap_details, play_recap_without_index) # array [('name','ok','changed','unreachable', 'failed', 'skipped'. 'rescued'. 'ignored')]

					ansible_inventory_scope_content = "[scope]"
					# index fqdn: 0, ok: 1, changed: 2, unreachable: 3, failed: 4, skipped: 5, rescued: 6, ignored: 7
					for machine in machines_match:
						if int(machine[1]) == 0:
							ansible_inventory_scope_content += f"\n{machine[0]} ansible_ssh_private_key_file={self.path_rsa_vault_new + "/" + machine[0]}"
							pending += 1
						else:
							assets[machine[0]]['rsa_check_new'] = True

					with open(self.path_ansible_inventory_scope, 'w') as file:
						file.write(ansible_inventory_scope_content)

					connections = self.ansible_maximun_connections if pending == 0 else connections + 1

		for k, v in assets.items():
			if not v['rsa_check_new']:
				os.remove(self.path_rsa_vault_new + "/" + k)
				os.remove(self.path_rsa_vault_new + "/" + k + ".pub")

		if os.path.exists(self.path_ansible_inventory_scope):
			os.remove(self.path_ansible_inventory_scope)

	def _rsa_key_delete(self, assets):
		connections = 0 # current try

		# create ansible inventory with all the assets
		ansible_inventory_scope_content = "[scope]"
		for k, v in assets.items():
			if v['rsa_check_new'] and os.path.exists(self.path_rsa_vault_backup + "/" + k):
				assets[k]['rsa_old_exists'] = True
				ansible_inventory_scope_content += f"\n{k} ansible_ssh_private_key_file={self.path_rsa_vault_new + "/" + k} rsa_key_file={self.path_rsa_vault_backup + "/" + k}.pub"

		with open(self.path_ansible_inventory_scope, 'w') as file:
			file.write(ansible_inventory_scope_content)

		while connections < self.ansible_maximun_connections:
			pending = 0 # pending assets to check
			command = f"ansible-playbook -i {self.path_app + "/" + self.path_ansible_inventory_all} -i {self.path_app + "/" + self.path_ansible_inventory_scope} {self.path_app + "/" + self.path_ansible_playbook}/ssh_key_delete.yml"
			result = subprocess.run(command, shell=True, capture_output=True, text=True)

			# searching section
			play_recap_match = re.search(self.ansible_pattern_play_recap, result.stdout)

			if play_recap_match:
				play_recap = play_recap_match.group(0) # get the string from 'PLAY RECAP' until the end of the file
				play_recap_lines = play_recap.splitlines() # split on lines

				if play_recap_lines:
					play_recap_lines.pop(0) # remove first line 'PLAY RECAP'
					play_recap_without_index = "\n".join(play_recap_lines) # array to string to apply pattern
					machines_match = re.findall(self.ansible_pattern_play_recap_details, play_recap_without_index) # array [('name','ok','changed','unreachable', 'failed', 'skipped'. 'rescued'. 'ignored')]

					ansible_inventory_scope_content = "[scope]"
					# index fqdn: 0, ok: 1, changed: 2, unreachable: 3, failed: 4, skipped: 5, rescued: 6, ignored: 7
					for machine in machines_match:
						if int(machine[1]) == 0:
							ansible_inventory_scope_content += f"\n{machine[0]} ansible_ssh_private_key_file={self.path_rsa_vault_new + "/" + machine[0]} rsa_key_file={self.path_rsa_vault_backup + "/" + k}.pub"
							pending += 1
						else:
							assets[machine[0]]['rsa_old_deleted'] = True

					with open(self.path_ansible_inventory_scope, 'w') as file:
						file.write(ansible_inventory_scope_content)

					connections = self.ansible_maximun_connections if pending == 0 else connections + 1

		for k, v in assets.items():
			if v['rsa_check_new'] and v['rsa_old_exists'] and not v['rsa_old_deleted']: # if not deleted: backup to archive
				os.rename(self.path_rsa_vault_backup + "/" + k, self.path_rsa_vault_archive + "/" + self.now + "_" + k)
				os.rename(self.path_rsa_vault_backup + "/" + k + ".pub", self.path_rsa_vault_archive + "/" + self.now + "_" + k + ".pub")

		if os.path.exists(self.path_ansible_inventory_scope):
			os.remove(self.path_ansible_inventory_scope)

	def _rsa_key_reorder(self, assets):
		for k, v in assets.items():
			if v['rsa_check_new']:
				# live to backup
				os.rename(self.path_rsa_vault_live + "/" + k, self.path_rsa_vault_backup + "/" + k)
				os.rename(self.path_rsa_vault_live + "/" + k + ".pub", self.path_rsa_vault_backup + "/" + k + ".pub")

				# new to live
				os.rename(self.path_rsa_vault_new + "/" + k, self.path_rsa_vault_live + "/" + k)
				os.rename(self.path_rsa_vault_new + "/" + k + ".pub", self.path_rsa_vault_live + "/" + k + ".pub")

	def _rsa_regenerate_log(self, assets):
		log = "machine;rsa_updated;rsa_check_new;rsa_old_exists;rsa_old_deleted;comments"
		for k, v in assets.items():
			log += f"\n{k};{v["rsa_updated"]};{v["rsa_check_new"]};{v["rsa_old_exists"]};{v["rsa_old_deleted"]};"
			if v['rsa_updated']:
				if v['rsa_check_new']:
					if v['rsa_old_exists']:
						if v['rsa_old_deleted']:
							log += f"process_end_properly_backup_key_exists_and_was_removed"
						else:
							log += f"process_end_properly_backup_key_exist_but_was_not_removed_archived_{self.now}_{k}"
					else:
						log += f"process_end_properly_backup_key_didnt_exist"
				else:
					log += f"double_check_didnt_work"
			else:
				log += f"key_was_not_updated"

		with open(self.path_log + "/" + self.now + "_" + "rsa_regenerate.csv", 'w') as file:
			file.write(log + "\n")
			
		print(f"log created: {self.path_log + "/" + self.now + "_" + "rsa_regenerate.csv"}")