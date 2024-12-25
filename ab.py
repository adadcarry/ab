import requests
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
import time

# 初始化 Web3
w3 = Web3(Web3.HTTPProvider("https://arbitrum.llamarpc.com"))

# 基础配置
BASE_URL = "https://api.deform.cc/"
HEADERS_COMMON = {
    "origin": "https://abstract.deform.cc",
    "referer": "https://abstract.deform.cc/"
}

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

# 重试机制
def retry_request(func, *args, retries=3, delay=2, **kwargs):
    for attempt in range(retries):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429 and attempt < retries - 1:
                print("429 Too Many Requests. Retrying...")
                time.sleep(delay)
            else:
                raise e

# 登录并获取 Token
def login_and_get_token(wallet_address, private_key):
    # 请求初始化
    url_init = "https://auth.privy.io/api/v1/siwe/init"
    payload_init = {"address": wallet_address}
    response = retry_request(requests.post, url_init, headers=HEADERS_COMMON, json=payload_init)
    response.raise_for_status()
    data = response.json()
    nonce, expires_at = data["nonce"], data["expires_at"]

    # 签名
    message = f"""abstract.deform.cc wants you to sign in with your Ethereum account:\n{wallet_address}\n\nBy signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.\n\nURI: https://abstract.deform.cc\nVersion: 1\nChain ID: 42161\nNonce: {nonce}\nIssued At: {expires_at}"""
    encoded_message = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(encoded_message, private_key=private_key)

    # 验证签名
    url_auth = "https://auth.privy.io/api/v1/siwe/authenticate"
    payload_auth = {
        "message": message,
        "signature": f"0x{signed_message.signature.hex()}",
        "chainId": "eip155:42161",
        "walletClientType": "okx_wallet",
        "connectorType": "injected"
    }
    response = retry_request(requests.post, url_auth, headers=HEADERS_COMMON, json=payload_auth)
    response.raise_for_status()
    tokens = response.json()
    return tokens["token"], tokens["identity_token"]

# 验证活动
def verify_activity(activity_id, token, identity_token, referral_code=None):
    headers = {
        **HEADERS_COMMON,
        "authorization": f"Bearer {token}",
        "privy-id-token": identity_token,
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
    response = retry_request(requests.post, BASE_URL, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

# 执行主逻辑
if __name__ == "__main__":
    private_keys = load_private_keys()
    activity_id = "ff4d031f-c16b-4137-8cac-efc8983771e5"
    referral_code = "Z7v19LJO2bKJ"  # 替换为所需邀请码

    for private_key in private_keys:
        try:
            # 获取钱包地址
            account = Account.from_key(private_key)
            wallet_address = account.address
            print(f"正在处理钱包地址: {wallet_address}")

            # 登录并获取 token
            token, identity_token = login_and_get_token(wallet_address, private_key)

            # 验证任务
            response_data = verify_activity(activity_id, token, identity_token, referral_code)
            print(f"钱包 {wallet_address} 的任务完成，结果: {response_data}")

            # 每分钟处理一个地址
            time.sleep(60)
        except Exception as e:
            print(f"处理钱包 {wallet_address} 时出错: {str(e)}")
