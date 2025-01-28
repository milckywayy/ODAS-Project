
def get_device_info(user_agent):
    return f'{user_agent.device.family}, {user_agent.os.family}, {user_agent.os.version_string}'
