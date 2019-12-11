from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpRequest


class MessagingRequest(HttpRequest):
    session = 'session'

    def __init__(self):
        super().__init__()
        self._messages = FallbackStorage(self)

    def get_messages(self):
        return getattr(self._messages, '_queued_messages')

    def get_message_strings(self):
        return [str(m) for m in self.get_messages()]
