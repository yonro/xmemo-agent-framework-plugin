"""Conservative byte budget includes serialized provenance and truncation flags.

One UTF-8 byte is charged as one token. This deliberately overestimates ordinary
text; it is not a model tokenizer or a model-specific context-window guarantee.
"""
from dataclasses import replace


def apply_budget(items, *, max_items, max_tokens):
    kept = []
    used = 0
    for item in items[:max_items]:
        remaining = max_tokens - used
        if len(item.render().encode()) > remaining:
            lo, hi = 0, len(item.text)
            while lo < hi:
                mid = (lo + hi + 1) // 2
                candidate = replace(item, text=item.text[:mid], truncated=True)
                if len(candidate.render().encode()) <= remaining:
                    lo = mid
                else:
                    hi = mid - 1
            item = replace(item, text=item.text[:lo], truncated=True)
            if not item.text or len(item.render().encode()) > remaining:
                break
        kept.append(item)
        used += len(item.render().encode())
    dropped = len(items) - len(kept)
    return tuple(kept), dropped, bool(dropped or any(x.truncated for x in kept)), used
