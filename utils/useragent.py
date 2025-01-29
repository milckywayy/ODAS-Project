def get_device_info(user_agent):
    device = user_agent.device.family or "Unknown Device"
    os_family = user_agent.os.family or "Unknown OS"
    os_version = user_agent.os.version_string or "Unknown Version"
    browser = user_agent.browser.family or "Unknown Browser"
    browser_version = user_agent.browser.version_string or "Unknown Browser Version"

    return f"Device: {device}, OS: {os_family} {os_version}, Browser: {browser} {browser_version}"
