API
===

Abstract Base Classes
---------------------

.. autoclass:: eth_enr.abc.CommonENRAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.UnsignedENRAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.ENRAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.ENRManagerAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.IdentitySchemeAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.IdentitySchemeRegistryAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.ENRDatabaseAPI
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.abc.QueryableENRDatabaseAPI
    :members:
    :undoc-members:
    :show-inheritance:


Classes
-------

.. autoclass:: eth_enr.enr.ENR
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.enr.UnsignedENR
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.enr_manager.ENRManager
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.identity_schemes.IdentitySchemeRegistry
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.identity_schemes.V4IdentityScheme
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.identity_schemes.V4CompatIdentityScheme
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.enr_db.ENRDB
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.query_db.QueryableENRDB
    :members:
    :undoc-members:
    :show-inheritance:


Constraints
-----------


.. autoclass:: eth_enr.constraints.KeyExists
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.constraints.HasUDPIPv4Endpoint
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.constraints.HasUDPIPv6Endpoint
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.constraints.HasTCPIPv4Endpoint
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.constraints.HasTCPIPv6Endpoint
    :members:
    :undoc-members:
    :show-inheritance:


Exceptions
----------


.. autoclass:: eth_enr.exceptions.OldSequenceNumber
    :members:
    :undoc-members:
    :show-inheritance:


.. autoclass:: eth_enr.exceptions.UnknownIdentityScheme
    :members:
    :undoc-members:
    :show-inheritance:
