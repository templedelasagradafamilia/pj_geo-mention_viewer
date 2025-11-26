import csv
import yaml
from streamlit_authenticator.utilities.hasher import Hasher

users_csv_path = "user_info.csv"
config_yaml_path = "config.yaml"

# CSV 読み込み
with open(users_csv_path, "r") as f:
    csvreader = csv.DictReader(f)
    users = list(csvreader)

# yaml 読み込み
with open(config_yaml_path, "r") as f:
    yaml_data = yaml.safe_load(f)

# パスワードのハッシュ化
users_dict = {}
for user in users:
    hashed_pw = Hasher.hash(user["password"])
    users_dict[user["id"]] = {
        "name": user.get("name", user["id"]),  # name が無ければ id をそのまま表示名に使う
        "password": hashed_pw,
        # "email" は無しでもOK
    }

# yaml 書き込み
yaml_data["credentials"]["usernames"] = users_dict
with open(config_yaml_path, "w") as f:
    yaml.dump(yaml_data, f, sort_keys=False, allow_unicode=True)
    print("完了")
