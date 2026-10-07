from email import message_from_binary_file, message_from_bytes, message_from_file, message_from_string

def probe():
    return (
        message_from_binary_file,
        message_from_bytes,
        message_from_file,
        message_from_string,
    )
