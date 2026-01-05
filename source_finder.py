# -*- coding: utf-8 -*-
import json, re, urllib.parse, urllib.request

def _normalize_text(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[（(].*?[）)]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s

def parse_filename_to_artist_title(filename: str):
    name = filename
    if "." in name:
        name = name.rsplit(".", 1)[0]
    if " - " in name:
        left, right = name.split(" - ", 1)
        return _normalize_text(left), _normalize_text(right)
    return "", _normalize_text(name)

def _qq_search_api(artist: str, title: str, limit: int = 5):
    query = (artist + " " + title).strip() if artist or title else title
    if not query:
        return None
    base = "https://c.y.qq.com/soso/fcgi-bin/client_search_cp"
    params = {"format": "json", "p": "1", "n": str(limit), "w": query}
    url = base + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0", "Referer": "https://y.qq.com/", "Origin": "https://y.qq.com"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read().decode("utf-8", errors="ignore")
        return json.loads(raw)

def _best_match_songmid(resp_json, artist: str, title: str):
    try:
        songs = resp_json["data"]["song"]["list"]
    except Exception:
        return None
    artist_l, title_l = artist.lower(), title.lower()
    best_mid = None
    for item in songs:
        name = str(item.get("songname", ""))
        name_l = name.lower()
        singers = item.get("singer", []) or []
        singer_names = " ".join([s.get("name", "") for s in singers]).lower()
        mid = item.get("songmid") or item.get("mid")
        if not mid:
            continue
        if title_l and title_l in name_l and (not artist_l or artist_l in singer_names):
            return mid
        if best_mid is None and title_l and title_l in name_l:
            best_mid = mid
        if best_mid is None and artist_l and artist_l in singer_names:
            best_mid = mid
        if best_mid is None:
            best_mid = mid
    return best_mid

def guess_song_url(file_basename: str) -> str | None:
    artist, title = parse_filename_to_artist_title(file_basename)
    resp = _qq_search_api(artist, title)
    if not resp:
        return None
    mid = _best_match_songmid(resp, artist, title)
    if not mid:
        return None
    return f"https://y.qq.com/n/ryqq/songDetail/{mid}"
