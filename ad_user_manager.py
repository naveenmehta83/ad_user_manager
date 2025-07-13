import yaml
import argparse
import os
import getpass
import pandas as pd
import hvac
import logging
from logging.handlers import TimedRotatingFileHandler
from pyad import aduser, adgroup, adcontainer, adbase

# -------------------------------
# Logging Setup
# -------------------------------
def setup_logger():
    os.makedirs("logs", exist_ok=True)
    log_file = "logs/ad_tasks.log"
    logger = logging.getLogger("ADLogger")
    logger.setLevel(logging.DEBUG)
    handler = TimedRotatingFileHandler(log_file, when="midnight", backupCount=7)
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

# -------------------------------
# Vault Config & Secret Loader
# -------------------------------
def load_vault_config(file_path):
    with open(file_path, "r") as f:
        return yaml.safe_load(f)["vault"]

def get_ad_secrets_from_vault(vault_cfg):
    client = hvac.Client(url=vault_cfg["url"], token=vault_cfg["token"])
    if not client.is_authenticated():
        raise Exception("Vault authentication failed.")
    secret = client.secrets.kv.v2.read_secret_version(path=vault_cfg["secret_path"])
    return secret["data"]["data"]  # return a dict with credentials

# -------------------------------
# AD Setup & User File Loader
# -------------------------------
def set_ad_defaults(ldap_server, username, password):
    adbase.set_defaults(ldap_server=ldap_server, username=username, password=password)

def load_users(file_path):
    ext = os.path.splitext(file_path)[-1].lower()
    if ext == ".csv":
        df = pd.read_csv(file_path)
    elif ext == ".xlsx":
        df = pd.read_excel(file_path)
    else:
        raise ValueError("Only .csv and .xlsx files are supported.")
    return df.fillna("").to_dict(orient="records")

# -------------------------------
# AD Operations
# -------------------------------
def create_user(user, logger):
    try:
        container = adcontainer.ADContainer.from_dn(user["ou"])
        obj = aduser.ADUser.create(user["cn"], container, password=user["password"], optional_attributes={
            "displayName": user.get("display_name", user["cn"])
        })
        logger.info(f"Created user: {obj.get_attribute('distinguishedName')}")
    except Exception as e:
        logger.error(f"Create failed for {user['cn']}: {e}")

def delete_user(cn, logger):
    try:
        obj = aduser.ADUser.from_cn(cn)
        obj.delete()
        logger.info(f"Deleted user: {cn}")
    except Exception as e:
        logger.error(f"Delete failed for {cn}: {e}")

def modify_user(cn, attr, value, logger):
    try:
        obj = aduser.ADUser.from_cn(cn)
        obj.update_attribute(attr, value)
        logger.info(f"Modified {cn}: {attr} = {value}")
    except Exception as e:
        logger.error(f"Modify failed for {cn}: {e}")

def add_user_to_groups(cn, groups_str, logger):
    if not groups_str:
        return
    groups = [g.strip() for g in groups_str.split(",") if g.strip()]
    try:
        user = aduser.ADUser.from_cn(cn)
        for grp in groups:
            group = adgroup.ADGroup.from_cn(grp)
            group.add_members([user])
            logger.info(f"Added {cn} to group {grp}")
    except Exception as e:
        logger.error(f"Add to group failed for {cn}: {e}")

def remove_user_from_groups(cn, groups_str, logger):
    if not groups_str:
        return
    groups = [g.strip() for g in groups_str.split(",") if g.strip()]
    try:
        user = aduser.ADUser.from_cn(cn)
        for grp in groups:
            group = adgroup.ADGroup.from_cn(grp)
            group.remove_members([user])
            logger.info(f"Removed {cn} from group {grp}")
    except Exception as e:
        logger.error(f"Remove from group failed for {cn}: {e}")

# -------------------------------
# Process User Tasks
# -------------------------------
def process_users(users, logger):
    for user in users:
        action = user.get("action", "").strip().lower()
        cn = user.get("cn", "").strip()

        if not action or not cn:
            logger.warning("Missing 'action' or 'cn' field in a row. Skipped.")
            continue

        try:
            if action == "create":
                create_user(user, logger)
                add_user_to_groups(cn, user.get("add_to_groups"), logger)

            elif action == "delete":
                delete_user(cn, logger)

            elif action == "modify":
                modify_user(cn, user.get("attr"), user.get("value"), logger)
                add_user_to_groups(cn, user.get("add_to_groups"), logger)
                remove_user_from_groups(cn, user.get("remove_from_groups"), logger)

            else:
                logger.warning(f"Unknown action '{action}' for user '{cn}'")

        except Exception as e:
            logger.error(f"Unexpected error for {cn}: {e}")

# -------------------------------
# Main
# -------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Active Directory Automation with Vault & Excel/CSV")
    parser.add_argument("--vault", required=True, help="Path to vault_config.yaml")
    parser.add_argument("--users", required=True, help="Path to users.xlsx or users.csv")
    args = parser.parse_args()

    logger = setup_logger()

    try:
        if not os.path.exists(args.vault) or not os.path.exists(args.users):
            logger.error("Missing vault config or users file.")
            exit(1)

        vault_cfg = load_vault_config(args.vault)
        ad_secrets = get_ad_secrets_from_vault(vault_cfg)
        users = load_users(args.users)

        set_ad_defaults(ad_secrets["ldap_server"], ad_secrets["domain_user"], ad_secrets["domain_pass"])

        process_users(users, logger)

    except Exception as e:
        logger.critical(f"Fatal error: {e}")
