import requests
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import json
from datetime import datetime

# 初始化Web3实例
w3 = Web3(Web3.HTTPProvider("https://arbitrum.llamarpc.com"))

# 读取私钥文件
def load_private_keys(file_path="private_key.txt"):
    try:
        with open(file_path, "r") as file:
            private_keys = [line.strip() for line in file if line.strip()]
        if not private_keys:
            raise ValueError("私钥文件为空，请检查文件内容")
        return private_keys
    except FileNotFoundError:
        raise FileNotFoundError(f"无法找到私钥文件: {file_path}")
    except Exception as e:
        raise Exception(f"读取私钥文件时出错: {str(e)}")

# 登录并获取 Token
def login_and_get_token(wallet_address, private_key):
    url_init = "https://auth.privy.io/api/v1/siwe/init"
    headers_init = {
        "Content-Type": "application/json",
        "origin": "https://abstract.deform.cc",
        "referer": "https://abstract.deform.cc/"
    }
    payload_init = {"address": wallet_address}
    response = requests.post(url_init, headers=headers_init, json=payload_init)
    response.raise_for_status()
    data = response.json()
    nonce, expires_at = data["nonce"], data["expires_at"]

    message = f"""abstract.deform.cc wants you to sign in with your Ethereum account:\n{wallet_address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://abstract.deform.cc\nVersion: 1\nChain ID: 42161\nNonce: {nonce}\nIssued At: {expires_at}\nResources:\n- https://privy.io"""

    encoded_message = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(encoded_message, private_key=private_key)
    signature = f"0x{signed_message.signature.hex()}"

    url_auth = "https://auth.privy.io/api/v1/siwe/authenticate"
    headers_auth = {
        "Content-Type": "application/json",
        "origin": "https://abstract.deform.cc",
        "referer": "https://abstract.deform.cc/"
    }
    payload_auth = {
        "message": message,
        "signature": signature,
        "chainId": "eip155:42161",
        "walletClientType": "okx_wallet",
        "connectorType": "injected"
    }
    response = requests.post(url_auth, headers=headers_auth, json=payload_auth)
    response.raise_for_status()
    tokens = response.json()
    return tokens["token"], tokens["identity_token"]

# 验证活动
def verify_activity(activity_id, token, identity_token, referral_code=None):
    url = "https://api.deform.cc/"
    headers = {
        "authorization": f"Bearer {token}",
        "privy-id-token": identity_token,
        "origin": "https://abstract.deform.cc",
        "referer": "https://abstract.deform.cc/",
        "Content-Type": "application/json"
    }
    payload = {
        "operationName": "VerifyActivity",
        "variables": {
            "data": {
                "activityId": activity_id,
                "metadata": {"referralCode": referral_code} if referral_code else {}
            }
        },
        "query": "mutation VerifyActivity($data: VerifyActivityInput!) { verifyActivity(data: $data) { ... } }"
    }
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

# 主逻辑
def main():
    private_keys = load_private_keys()
    activity_ids = [
        "ff4d031f-c16b-4137-8cac-efc8983771e5",
        "ef348b9f-20b1-41f7-929d-09d4f163cc0d" # 添加其他任务的ID
    ]
    referral_code = "Z7v19LJO2bKJ"  # 替换为所需邀请码

    for private_key in private_keys:
        try:
            account = Account.from_key(private_key)
            wallet_address = account.address
            print(f"正在处理钱包地址: {wallet_address}")

            token, identity_token = login_and_get_token(wallet_address, private_key)

            for activity_id in activity_ids:
                response_data = verify_activity(activity_id, token, identity_token, referral_code)
                print(f"活动 {activity_id} 完成，结果: {response_data}")
        except Exception as e:
            print(f"处理钱包地址 {wallet_address} 时出错: {str(e)}")

if __name__ == "__main__":
    main()
