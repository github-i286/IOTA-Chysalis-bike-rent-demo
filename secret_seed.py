#!/usr/bin/python
import hashlib
import random
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature


# secret seeds fort test IOTA on Chrysalis Mainnet
# enter random 64 character from 0..9 and a..f
# Sample     = '8923afebce62009fa44128bef6733109127655f5e5d55412dcb5a21012399231'
# do NOT use this sample
seedAccountA = '<random string with 0..9 and a..f                               '
seedAccountB = '<random string with 0..9 and a..f                               '

fire_fly_return_address = 'iota1 <your firefly account adress to return your IOTAs'

own_node_url = '<https://your-node.com'

def public_key(private_key):
    # create a private / public key pair
    curve = ec.SECP256R1()
    signature_algorithm = ec.ECDSA(hashes.SHA256())
    private_key = ec.derive_private_key(private_key, curve, default_backend())
    return private_key.public_key()

# This is a random lagre integer value like: 0x123fbde67123abde662123
# do NOT use this sample
private_key_value_text_bike_operator = 0x123fbde67123abde662123
def public_key_value_text_bike_operator() -> ec.EllipticCurvePublicKey: 
    return public_key(private_key_value_text_bike_operator)

# This is a random lagre integer value like: 0xf565681230bce800213123
# do NOT use this sample
private_key_value_text_bike_user = 0xf565681230bce800213123
def public_key_value_text_bike_operator() -> ec.EllipticCurvePublicKey: 
    return public_key(private_key_value_text_bike_user)

