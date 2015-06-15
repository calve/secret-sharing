# -*- coding: utf-8 -*-
"""
    Secret Sharing
    ~~~~~

    :copyright: (c) 2014 by Halfmoon Labs
    :license: MIT, see LICENSE for more details.
"""

import string

from utilitybelt3 import int_to_charset, charset_to_int, base58_chars, \
    base32_chars, zbase32_chars
from .primes import get_large_enough_prime
from .polynomials import random_polynomial, \
    get_polynomial_points, modular_lagrange_interpolation
import random


def secret_int_to_points(secret_int, point_threshold, num_points, verifiable=False):
    """ Split a secret (integer) into shares (pair of integers / x,y coords).

        Sample the points of a random polynomial with the y intercept equal to
        the secret int.

        If verifiable is set to True, this function will return a tuple of the form
        (points, g, p, commitments) where g, p and commitments can be publically shared.
        It implement's the Feldman's scheme :
        We pick a random generator g, and for each share (x, y), we compute the
        (non reversible) modular exponentiation ``g^y mod p``.
    """
    if point_threshold < 2:
        raise ValueError("Threshold must be >= 2.")
    if point_threshold > num_points:
        raise ValueError("Threshold must be < the total number of points.")
    prime = get_large_enough_prime([secret_int, num_points])
    if not prime:
        raise ValueError("Error! Secret is too long for share calculation!")
    coefficients = random_polynomial(point_threshold-1, secret_int, prime)
    points = get_polynomial_points(coefficients, num_points, prime)
    if verifiable:
        g = random.randrange(1, prime-1)
        commitments = []
        for x, y in points:
            r = pow(g, y, prime)
            commitments.append((x, r))
        return points, g, prime, commitments
    else:
        return points


def points_to_secret_int(points):
    """ Join int points into a secret int.

        Get the intercept of a random polynomial defined by the given points.
    """
    if not isinstance(points, list):
        raise ValueError("Points must be in list form.")
    for point in points:
        if not isinstance(point, tuple) and len(point) == 2:
            raise ValueError("Each point must be a tuple of two values.")
        if not (isinstance(point[0], int) and
                isinstance(point[1], int)):
            raise ValueError("Each value in the point must be an int.")
    x_values, y_values = list(zip(*points))
    prime = get_large_enough_prime(y_values)
    free_coefficient = modular_lagrange_interpolation(0, points, prime)
    secret_int = free_coefficient  # the secret int is the free coefficient
    return secret_int


def point_to_share_string(point, charset):
    """ Convert a point (a tuple of two integers) into a share string - that is,
        a representation of the point that uses the charset provided.
    """
    # point should be in the format (1, 4938573982723...)
    if '-' in charset:
        raise ValueError(
            'The character "-" cannot be in the supplied charset.')
    if not (isinstance(point, tuple) and len(point) == 2 and
            isinstance(point[0], int) and
            isinstance(point[1], int)):
        raise ValueError(
            'Point format is invalid. Must be a pair of integers.')
    x, y = point
    x_string = int_to_charset(x, charset)
    y_string = int_to_charset(y, charset)
    share_string = x_string + '-' + y_string
    return share_string


def share_string_to_point(share_string, charset):
    """ Convert a share string to a point (a tuple of integers).
    """
    # share should be in the format "01-d051080de7..."
    if '-' in charset:
        raise ValueError(
            'The character "-" cannot be in the supplied charset.')
    if not isinstance(share_string, str) and share_string.count('-') == 1:
        raise ValueError('Share format is invalid.')
    x_string, y_string = share_string.split('-')
    if (set(x_string) - set(charset)) or (set(y_string) - set(charset)):
        raise ValueError("Share has characters that aren't in the charset.")
    x = charset_to_int(x_string, charset)
    y = charset_to_int(y_string, charset)
    return (x, y)


class SecretSharer():
    """ Creates a secret sharer, which can convert from a secret string to a
        list of shares and vice versa. The splitter is initialized with the
        character set of the secrets and the character set of the shares that
        it expects to be dealing with.
    """
    secret_charset = string.hexdigits[0:16]
    share_charset = string.hexdigits[0:16]

    def __init__(self):
        pass

    @classmethod
    def split_secret(cls, secret_string, share_threshold, num_shares):
        secret_int = charset_to_int(secret_string, cls.secret_charset)
        points = secret_int_to_points(secret_int, share_threshold, num_shares)
        shares = []
        for point in points:
            shares.append(point_to_share_string(point, cls.share_charset))
        return shares

    @classmethod
    def split_verifiable_secret(cls, secret_string, share_threshold, num_shares):
        secret_int = charset_to_int(secret_string, cls.secret_charset)
        points, g, p, commitments = secret_int_to_points(secret_int, share_threshold, num_shares, verifiable=True)
        shares = []
        final_commitments = []
        for point in points:
            shares.append(point_to_share_string(point, cls.share_charset))
        for commitment in commitments:
            final_commitments.append(point_to_share_string(commitment, cls.secret_charset))
        final_g = int_to_charset(g, cls.share_charset)
        final_p = int_to_charset(p, cls.share_charset)
        return shares, final_g, final_p, final_commitments

    @classmethod
    def verify(cls, share_string, commitments, g_string, p_string):
        g = charset_to_int(g_string, cls.share_charset)
        p = charset_to_int(p_string, cls.share_charset)
        x_string, y_string = share_string.split('-')
        for commitment in commitments:
            x_commitment, y_commitment = commitment.split('-')
            if x_commitment == x_string:
                f = charset_to_int(y_commitment, cls.share_charset)
                break
        else:
            raise ValueError("Cannot find the part to verify this share")
        y = charset_to_int(y_string, cls.share_charset)
        return f == pow(g, y, p)


    @classmethod
    def recover_secret(cls, shares):
        points = []
        for share in shares:
            points.append(share_string_to_point(share, cls.share_charset))
        secret_int = points_to_secret_int(points)
        secret_string = int_to_charset(secret_int, cls.secret_charset)
        return secret_string


class HexToHexSecretSharer(SecretSharer):
    """ Standard sharer for converting hex secrets to hex shares.
    """
    secret_charset = string.hexdigits[0:16]
    share_charset = string.hexdigits[0:16]


class PlaintextToHexSecretSharer(SecretSharer):
    """ Good for converting secret messages into standard hex shares.
    """
    secret_charset = string.printable
    share_charset = string.hexdigits[0:16]


class BitcoinToB58SecretSharer(SecretSharer):
    """ Good for converting Bitcoin secret keys into shares that can be
        reliably printed out in any font.
    """
    secret_charset = base58_chars
    share_charset = base58_chars


class BitcoinToB32SecretSharer(SecretSharer):
    """ Good for converting Bitcoin secret keys into shares that can be
        reliably and conveniently transcribed.
    """
    secret_charset = base58_chars
    share_charset = base32_chars


class BitcoinToZB32SecretSharer(SecretSharer):
    """ Good for converting Bitcoin secret keys into shares that can be
        reliably and conveniently transcribed.
    """
    secret_charset = base58_chars
    share_charset = zbase32_chars
