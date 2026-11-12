class AnyClientID(str):
    """A client_id value that will evaluate to True when compared to any str instance.

    Several sections of the code check an "aud" claim is the client_id.
    This makes unittests pass without the need to care what the client_id is.

    Examples:
    >>> AnyClientID() == "foo"
    True
    >>> AnyClientID() != "foo"
    False
    >>> AnyClientID() == 123
    False
    >>> AnyClientID() != 123
    True
    """

    def __eq__(self, other):
        return isinstance(other, str)

    def __ne__(self, other):
        return not isinstance(other, str)
