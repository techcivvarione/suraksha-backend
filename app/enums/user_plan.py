from enum import Enum


class UserPlan(str, Enum):
    FREE = "FREE"
    GO_PRO = "GO_PRO"
    GO_ULTRA = "GO_ULTRA"
