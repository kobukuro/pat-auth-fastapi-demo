from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

# 建立與資料庫的底層連線池
# 連線池：預設會維護多個連線，提升效能
engine = create_engine(settings.DATABASE_URL)
# 用來建立新的資料庫會話（Session）實例
#   - bind=engine：綁定到上面的引擎
#   - autocommit=False：不自動提交，需手動呼叫db.commit()
#   - autoflush=False：不自動將暫存的變更送出到資料庫
# 為什麼不自動提交？
#   讓開發者能完整掌控交易流程，若發生錯誤可以執行
#   db.rollback() 回滾變更。
# Flush：將Python物件的變更轉換成SQL指令，送出到資料庫執行，但還沒有提交交易。
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


# 在SQLAlchemy 的「宣告式映射」（Declarative Mapping）模式中
# 所有模型繼承同一個基底(這個Base class)
# Base會自動追蹤所有繼承它的模型類別
# 透過Base.metadata.create_all()可一次建立所有資料表
class Base(DeclarativeBase):
    pass

# 第一個Session：yield出來的型別是資料庫Session
# 後面兩個None：不接收任何值、不回傳任何值
def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        # 暫停函式執行，將 db 交給呼叫者（API路由函式）
        # API 執行完畢後，會回到這裡繼續執行
        # yield 讓 FastAPI 能夠：
        #   1. 在請求開始時取得資料庫連線
        #   2. 執行完 API 邏輯後
        #   3. 自動執行 finally 區塊清理資源
        yield db
    # 無論成功或失敗都會執行的區塊
    finally:
        # 關閉資料庫連線，將連線釋放回連線池
        db.close()
