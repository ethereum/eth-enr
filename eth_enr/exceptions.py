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


class DuplicateRecord(BaseENRException):
    """
    Raised when trying to set an ENR record to a database that already has a
    different record with the same sequence number.
    """

    pass
