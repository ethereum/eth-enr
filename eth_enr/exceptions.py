class BaseENRException(Exception):
    """
    Common base class for all library exceptions
    """

    pass


class UnknownIdentityScheme(BaseENRException):
    """
    Raised when trying to instantiate an ENR with an unknown identity scheme
    """

    pass


class OldSequenceNumber(BaseENRException):
    """
    Raised when trying to update an ENR record with a sequence number that is
    older than the latest sequence number we have seen
    """

    pass
