class AnyClientID(str):
    """A client_id value that will evaluate to True when compared to any str instance.

    Several sections of the code check an "aud" claim is the client_id.
    This makes unittests pass without the need to care what the client_id is.
    """

    def __eq__(self, other):
        return isinstance(other, str)
