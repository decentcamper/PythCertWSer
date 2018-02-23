import datetime  # we will use this for date objects

import os
import re
import json
import threading
from urlparse import urlparse

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64encode

default_headers = {}
class Person:
    def __init__(self,header_name=None, header_value=None, cookie=None):
  
        self.default_headers = {}
        if header_name is not None:
            self.default_headers[header_name] = header_value
        self.cookie = cookie
        # Set default User-Agent.
        self.user_agent = 'Swagger-Codegen/1.0.0/python'

    def set_default_header(self, header_name, header_value):
        default_headers[header_name] = header_value

    def get_sha256_digest(self, data):
        """
        :param data: Data set by User
        :return: instance of digest object
        """
        print('data', '{0}'.format(data))
        digest = SHA256.new()
        digest.update(data)
        return digest

    def get_rsasig_b64encode(self, private_key_path, digest):
        """
        :param private_key_path : abs path to private key .pem file.
        :param digest: digest
        :return: instance of digest object
        """

        key = open(private_key_path, "r").read()
        print('key', '{0}'.format(key))
        rsakey = RSA.importKey(key)
        signer = PKCS1_v1_5.new(rsakey)
        sign = signer.sign(digest)

        return b64encode(sign)

    def prepare_str_to_sign(self, req_tgt, hdrs):
        """
        :param req_tgt : Request Target as stored in http header.
        :param hdrs: HTTP Headers to be signed.
        :return: instance of digest object
        """
        ss = ""
        ss = ss + "(request-target): " + req_tgt.lower() + "\n"

        length = len(hdrs.items())

        i = 0
        for key, value in hdrs.items():
            ss = ss + key.lower() + ": " + value
            if i < length - 1:
                ss = ss + "\n"
            i += 1

        return ss

    def get_auth_header(self, hdrs, signed_msg):
        """
        This method prepares the Auth header string

        :param hdrs : HTTP Headers
        :param signed_msg: Signed Digest
        :return: instance of digest object
        """

        auth_str = ""
        auth_str = auth_str + "Signature"

        auth_str = auth_str + " " + "keyId=\"" + self.api_key_id + "\"," + "algorithm=\"" + self.digest_algorithm + "\"," + "headers=\"(request-target)"

        for key, _ in hdrs.items():
            auth_str = auth_str + " " + key.lower()
        auth_str = auth_str + "\""

        auth_str = auth_str + "," + "signature=\"" + signed_msg.decode('ascii') + "\""

        return auth_str

    def prepare_auth_header(self, resource_path, method, body=None, query_params=None, private_key_file=None,api_key_id=None,host=None,ne_location=None,base_path=None):
        """
        Method to perform operations required to prepare the auth header and eventually
        add the signed headers to default_header object used by ApiClient class.

        :param resource_path : resource path which is the api being called upon.
        :param method: request type
        :param body: body passed in the http request.
        :param query_params: query parameters used by the API
        :return: instance of digest object
        """
        
        
        self.api_key_id = api_key_id
        self.digest_algorithm = "rsa-sha256"
        self.host = host
        

        if body is None:
            body = ''
        else:
            body = json.dumps(body)
        
        target_host = ne_location
        target_path = base_path

        request_target = method + " " + target_path + resource_path

        if query_params:
            raw_query = urlencode(query_params).replace('+', '%20')
            request_target += "?" + raw_query

        from email.utils import formatdate
        self.cdate = formatdate(timeval=None, localtime=False, usegmt=True)
        print('Date', '{0}'.format(self.cdate))

        # Setting the date object
        # myObject.setCdate(format(self.cdate));

        request_body = body.encode()
        print('request_body', '{0}'.format(request_body))
        body_digest = self.get_sha256_digest(request_body)
        b64_body_digest = b64encode(body_digest.digest())

        # Setting the digest
        # myObject.setDigest("SHA-256=" + b64_body_digest.decode('ascii'))

        headers = {'Content-Type': 'application/json', 'Date': self.cdate, 'Host': target_host,
                   'Digest': "SHA-256=" + b64_body_digest.decode('ascii')}
        # headers = {'Content-Type': 'application/json', 'Host': target_host,
        # 'Digest': "SHA-256=" + b64_body_digest.decode('ascii')}

        string_to_sign = self.prepare_str_to_sign(request_target, headers)

        print('string_to_sign', '{0}'.format(string_to_sign))
        print('string_to_sign.encode', '{0}'.format(string_to_sign.encode()))

        digest = self.get_sha256_digest(string_to_sign.encode())

        b64_signed_msg = self.get_rsasig_b64encode(private_key_file, digest)

        auth_header = self.get_auth_header(headers, b64_signed_msg)

        # myObject.setAuthHeader(auth_header)
        self.set_default_header('Date', '{0}'.format(self.cdate))
        self.set_default_header('Host', '{0}'.format(target_host))
        self.set_default_header('Digest', 'SHA-256={0}'.format(b64_body_digest.decode('ascii')))
        self.set_default_header('Authorization', '{0}'.format(auth_header))
        return default_headers


