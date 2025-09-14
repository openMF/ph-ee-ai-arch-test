import os, json, time, logging, requests
log = logging.getLogger("slack")

SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_CHANNEL   = os.getenv("SLACK_CHANNEL", "#paymenthub_bot_alert")
SLACK_MENTION   = os.getenv("SLACK_MENTION", "")  # e.g. "<!channel>" for criticals

def _post_webhook(blocks):
    resp = requests.post(SLACK_WEBHOOK, json={"blocks": blocks}, timeout=10)
    resp.raise_for_status()
    return True

def _post_token(blocks):
    url = "https://slack.com/api/chat.postMessage"
    headers = {"Authorization": f"Bearer {SLACK_BOT_TOKEN}",
               "Content-Type": "application/json; charset=utf-8"}
    body = {"channel": SLACK_CHANNEL, "blocks": blocks, "unfurl_links": False, "unfurl_media": False}
    resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=10)
    ok = resp.json().get("ok", False)
    if not ok:
        log.error("Slack API error: %s", resp.text)
    return ok

def post(title, text, severity="info", facts=None, link=None, mention=False):
    """
    facts: list[(k,v)]
    severity: info|warn|crit
    """
    color_emoji = {"info":"ℹ️", "warn":"⚠️", "crit":"🚨"}.get(severity,"ℹ️")
    prefix = f"{color_emoji} {title}"
    if mention and SLACK_MENTION:
        text = f"{SLACK_MENTION}  {text}"

    # Build Slack Blocks
    fields = []
    if facts:
        for k,v in facts:
            fields.append({"type":"mrkdwn","text":f"*{k}:*\n{v}"})
    blocks = [
        {"type":"section","text":{"type":"mrkdwn","text":f"*{prefix}*"}},
        {"type":"section","text":{"type":"mrkdwn","text":text}},
    ]
    if fields:
        blocks.append({"type":"section","fields":fields})
    if link:
        blocks.append({"type":"context","elements":[{"type":"mrkdwn","text":f"🔗 {link}"}]})

    if SLACK_WEBHOOK:
        return _post_webhook(blocks)
    elif SLACK_BOT_TOKEN:
        return _post_token(blocks)
    else:
        log.warning("No Slack credentials configured; printing instead:\n%s", json.dumps(blocks, indent=2))
        return False
