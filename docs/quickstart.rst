Quickstart
==========

Simple ENR Creation
-------------------

Creating your first ENR record is as simple as:

.. doctest::

    >>> from eth_keys import keys
    >>> from eth_enr import ENRManager
    >>> private_key = keys.PrivateKey(b'unicornsrainbowsunicornsrainbows')
    >>> manager = ENRManager(private_key)
    >>> manager.enr
    enr:-HW4QDBN_uzB2BgXNgpjCN83hSE13oI46ZtFOmWnmYkGTZWrfRF6Yk60HcoiyuLDXqCTcj8fqk2DWetU2ZYJrXUEylIBgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6g
    >>> manager.enr.sequence_number
    1
    >>> manager.update((b'foo', b'bar'))
    enr:-H24QNUv1DBIpMITIUjJN8s7foWBJ33rR0liWCu4nVDaXk7ACcXpiMiFJHPC8UKTNkXfN3DXGwPX-Q6KL1uMZwNeyGMCg2Zvb4NiYXKCaWSCdjSJc2VjcDI1NmsxoQO98N2ifPfBQV3rqyKvP_drShGWxz2uUqnRJB4cSRwLqA
    >>> manager.enr[b'foo']
    b'bar'
    >>> manager.enr.sequence_number
    2


Manual ENR Creation
-------------------

You can forgo the :class:`~eth_enr.ENRManager` and create an ENR manually as follows:


.. doctest::

    >>> from eth_keys import keys
    >>> from eth_enr import UnsignedENR
    >>> private_key = keys.PrivateKey(b'unicornsrainbowsunicornsrainbows')
    >>> unsigned_enr = UnsignedENR(
    ... sequence_number=1,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key.public_key.to_compressed_bytes(),
    ... })
    >>> enr = unsigned_enr.to_signed_enr(private_key.to_bytes())
    >>> enr
    enr:-HW4QDBN_uzB2BgXNgpjCN83hSE13oI46ZtFOmWnmYkGTZWrfRF6Yk60HcoiyuLDXqCTcj8fqk2DWetU2ZYJrXUEylIBgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6g
