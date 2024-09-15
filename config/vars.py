ansible = {
    "maximun_connections": 3,
    "pattern_play_recap": r"PLAY RECAP[\s\S]*", # define regular expression to find 'PLAY RECAP' section
    "pattern_play_recap_details": r"(\S+)\s*:\s*ok=(\d+)\s*changed=(\d+)\s*unreachable=(\d+)\s*failed=(\d+)\s*skipped=(\d+)\s*rescued=(\d+)\s*ignored=(\d+)" # define a regular expression pattern to extract ansible details
}
default_user = "ansible"
path = {
    "ansible_inventory_all": "ansible/inventories/all.ini",
    "ansible_inventory_scope": "ansible/inventories/scope.ini",
    "ansible_inventory_scope_static": "ansible/inventories/scope_static.ini",
    "ansible_playbook": "ansible/playbook",
    "rsa_vault_archive": "~/.ssh/archive",
    "rsa_vault_backup": "~/.ssh/backup",
    "rsa_vault_live": "~/.ssh/live",
    "rsa_vault_new": "~/.ssh/new",
    "ssh_config": "~/.ssh/config",
    "log": "log"
}