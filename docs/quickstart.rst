Quickstart
==========


ENR Creation
------------

You can create an ENR record as follows.


.. doctest::

    >>> from eth_keys import keys
    >>> from eth_enr import UnsignedENR, ENR
    >>> private_key = keys.PrivateKey(b'unicornsrainbowsunicornsrainbows')
    >>> unsigned_enr = UnsignedENR(
    ... sequence_number=1,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key.public_key.to_compressed_bytes(),
    ...     b'unicorns': b'rainbows',
    ... })
    >>> enr = unsigned_enr.to_signed_enr(private_key.to_bytes())
    >>> enr
    enr:-Ie4QNRDUVEiOYTwwki59qs5SY_ofKSCbFL2BuslZ9fsZXGEMOlfxkFGpojFUj_ArnHMh4bv6E26frE1NII7z4xK9I0BgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6iIdW5pY29ybnOIcmFpbmJvd3M
    >>> enr == ENR.from_repr("enr:-Ie4QNRDUVEiOYTwwki59qs5SY_ofKSCbFL2BuslZ9fsZXGEMOlfxkFGpojFUj_ArnHMh4bv6E26frE1NII7z4xK9I0BgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6iIdW5pY29ybnOIcmFpbmJvd3M")  # recover an ENR from it's text representation
    True


Storing ENR records
-------------------

You can use the :class:`eth_enr.ENRDB` to store ENR records.  The underlying
storage is flexible and accepts any dictionary-like object.

.. doctest::

    >>> from eth_keys import keys
    >>> from eth_enr import UnsignedENR, ENRDB
    >>> private_key = keys.PrivateKey(b'unicornsrainbowsunicornsrainbows')
    >>> unsigned_enr = UnsignedENR(
    ... sequence_number=1,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key.public_key.to_compressed_bytes(),
    ... })
    >>> enr = unsigned_enr.to_signed_enr(private_key.to_bytes())
    >>> enr_db = ENRDB({})
    >>> enr_db.get_enr(enr.node_id)  # not yet in database
    Traceback (most recent call last):
      File "/home/piper/.pyenv/versions/3.6.9/lib/python3.6/doctest.py", line 1330, in __run
        compileflags, 1), test.globs)
      File "<doctest default[6]>", line 1, in <module>
        enr_db.get_enr(enr.node_id)  # not yet in database
      File "/home/piper/projects/eth-enr/eth_enr/enr_db.py", line 57, in get_enr
        return rlp.decode(self.db[self._get_enr_key(node_id)], sedes=ENR)  # type: ignore
    KeyError: b'l?\x85b\xc8\x03\xbf\xae5\xa8\xf5K\x85\x82\xa2\x89V\xb9%\x93M\x03\xdd\xb4Xu\xe1\x8e\x85\x93\x12\xc1:enr'
    >>> enr_db.set_enr(enr)
    >>> enr_db.get_enr(enr.node_id)
    enr:-HW4QDBN_uzB2BgXNgpjCN83hSE13oI46ZtFOmWnmYkGTZWrfRF6Yk60HcoiyuLDXqCTcj8fqk2DWetU2ZYJrXUEylIBgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6g
    >>> updated_enr = UnsignedENR(
    ... sequence_number=2,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key.public_key.to_compressed_bytes(),
    ... }).to_signed_enr(private_key.to_bytes())
    >>> enr_db.set_enr(updated_enr)
    >>> enr_db.set_enr(enr, raise_on_error=True)  # throws exception due to old sequence number
    Traceback (most recent call last):
      File "/home/piper/.pyenv/versions/3.6.9/lib/python3.6/doctest.py", line 1330, in __run
        compileflags, 1), test.globs)
      File "<doctest default[11]>", line 1, in <module>
        enr_db.set_enr(enr)  # throws exception due to old sequence number
      File "/home/piper/projects/eth-enr/eth_enr/enr_db.py", line 51, in set_enr
        f"Cannot overwrite existing ENR ({existing_enr.sequence_number}) with old one "
    eth_enr.exceptions.OldSequenceNumber: Cannot overwrite existing ENR (2) with old one (1)
    >>> assert enr_db.get_enr(updated_enr.node_id) == updated_enr


Using the ENRManager
--------------------

The :class:`eth_enr.ENRMAnager` automates creation, updating, and storage of ENR records.

.. doctest::

    >>> from eth_keys import keys
    >>> from eth_enr import ENRManager, ENRDB
    >>> private_key = keys.PrivateKey(b'unicornsrainbowsunicornsrainbows')
    >>> manager = ENRManager(private_key, ENRDB({}))
    >>> manager.enr
    enr:-HW4QDBN_uzB2BgXNgpjCN83hSE13oI46ZtFOmWnmYkGTZWrfRF6Yk60HcoiyuLDXqCTcj8fqk2DWetU2ZYJrXUEylIBgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6g
    >>> manager.enr.sequence_number
    1
    >>> manager.update((b'foo', b'bar'))
    >>> manager.enr
    enr:-H24QNUv1DBIpMITIUjJN8s7foWBJ33rR0liWCu4nVDaXk7ACcXpiMiFJHPC8UKTNkXfN3DXGwPX-Q6KL1uMZwNeyGMCg2Zvb4NiYXKCaWSCdjSJc2VjcDI1NmsxoQO98N2ifPfBQV3rqyKvP_drShGWxz2uUqnRJB4cSRwLqA
    >>> manager.enr[b'foo']
    b'bar'
    >>> manager.enr.sequence_number
    2
    >>> manager.update((b'foo', None))  # `None` triggers removal of a key.
    >>> manager.enr
    enr:-HW4QFeb9Qg_RNSWamKytj4Eh2eICVKSauQfp4PMY45YQdGzAyFnLjZBU-IuktiGKGiEz2nbEo6w4qNOu_D2Xdmr08gDgmlkgnY0iXNlY3AyNTZrMaEDvfDdonz3wUFd66sirz_3a0oRlsc9rlKp0SQeHEkcC6g
    >>> manager.enr[b'foo']
    Traceback (most recent call last):
      File "/home/piper/.pyenv/versions/3.6.9/lib/python3.6/doctest.py", line 1330, in __run
        compileflags, 1), test.globs)
      File "<doctest default[10]>", line 1, in <module>
        manager.enr[b'foo']
      File "/home/piper/projects/eth-enr/eth_enr/enr.py", line 93, in __getitem__
        return self._kv_pairs[key]
    KeyError: b'foo'


Querying ENR Records
--------------------

You can use the :class:`eth_enr.QueryableENRDB` which exposes the same API as
:class:`eth_enr.ENRDB` with one additional :meth:`eth_enr.QueryableENRDB.query`
method.

The :class:`eth_enr.QueryableENRDB` operates on top of any SQLite3 database
using the ``sqlite3`` standard library.


.. doctest::

    >>> import sqlite3
    >>> from eth_keys import keys
    >>> from eth_enr import UnsignedENR, QueryableENRDB
    >>> from eth_enr.constraints import KeyExists
    >>> private_key_a = keys.PrivateKey(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    >>> private_key_b = keys.PrivateKey(b'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB')
    >>> private_key_c = keys.PrivateKey(b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC')
    >>> enr_a = UnsignedENR(
    ... sequence_number=1,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key_a.public_key.to_compressed_bytes(),
    ...     b'unicorns': b'rainbows',
    ... }).to_signed_enr(private_key_a.to_bytes())
    >>> enr_b = UnsignedENR(
    ... sequence_number=7,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key_b.public_key.to_compressed_bytes(),
    ...     b'unicorns': b'rainbows',
    ...     b'cupcakes': b'sparkles',
    ... }).to_signed_enr(private_key_b.to_bytes())
    >>> enr_c = UnsignedENR(
    ... sequence_number=2,
    ... kv_pairs={
    ...     b'id': b'v4',
    ...     b'secp256k1': private_key_c.public_key.to_compressed_bytes(),
    ... }).to_signed_enr(private_key_c.to_bytes())
    >>> connection = sqlite3.connect(":memory:")
    >>> enr_db = QueryableENRDB(connection)
    >>> enr_db.set_enr(enr_a)
    >>> enr_db.set_enr(enr_b)
    >>> enrs_with_unicorns = tuple(enr_db.query(KeyExists(b'unicorns')))
    >>> assert enr_a in enrs_with_unicorns
    >>> assert enr_b in enrs_with_unicorns
    >>> assert enr_c not in enrs_with_unicorns
    >>> enrs_with_cupcakes = tuple(enr_db.query(KeyExists(b'cupcakes')))
    >>> assert enr_a not in enrs_with_cupcakes
    >>> assert enr_b in enrs_with_cupcakes
    >>> assert enr_c not in enrs_with_cupcakes
