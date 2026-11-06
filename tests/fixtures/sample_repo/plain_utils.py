def format_name(first: str, last: str) -> str:
    return f"{first} {last}"


def clamp(value: int, min_val: int, max_val: int) -> int:
    return max(min_val, min(max_val, value))
