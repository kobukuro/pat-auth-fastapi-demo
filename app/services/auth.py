import bcrypt


def hash_password(password: str) -> str:
    # bcrypt.gensalt()產生隨機的鹽值，每次執行都不同，用來防止彩虹表攻擊
    # .decode()將bcrypt.hashpw()回傳的bytes轉換成字串，方便存入資料庫
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
