# -*- coding: utf-8 -*-
#
# Copyright 2014 Google Inc. All rights reserved.
# Copyright 2018 Schatz Forensic Pty Ltd. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.

from __future__ import unicode_literals
from future import standard_library
standard_library.install_aliases()
from builtins import chr
import os
import re
import shutil
import string
import urllib.parse
import pyaff4
from pyaff4 import rdfvalue
from pyaff4 import utils


PRINTABLES = set(string.printable)
for i in "!$\\:*%?\"<>|]":
    PRINTABLES.discard(i)

PRINTABLES_NO_SLASH = PRINTABLES.copy()
PRINTABLES_NO_SLASH.discard('/')

FORBIDDEN = set()
for c in "<>\^`{|}":
    FORBIDDEN.add(c)

# convert a file path to an ARN fragment
# a basic implementation that aims for compatibility with OS specific implementations
# that produce file:// URI's
def arnPathFragment_from_path(pathName):
    escaped_path = []
    if pathName[0] == ".":
        if pathName[1] == ".":
            pathName = pathName[2:]
        else:
            pathName = pathName[1:]
    if pathName[0:3] == "\\\\.":
        escaped_path.append(".")
        pathName = pathName[3:]

    for c in pathName:
        if ord(c) >= 0 and ord(c)<= 0x1f:
            # control codes
            escaped_path.append("%%%02x" % ord(c))
        elif c == '\\':
            escaped_path.append("/")
        elif c == ' ':
            escaped_path.append("%20")
        elif c == '"':
            escaped_path.append("%22")
        elif c == '%':
            escaped_path.append("%25")
        elif c in FORBIDDEN:
            escaped_path.append("%%%02x" % ord(c))
        else:
            escaped_path.append(c)

    if escaped_path[0] == u"/":
        if len(escaped_path) > 1 and escaped_path[1] == u"/":
            # unc path
            escaped_path = escaped_path[2:]
            return "".join(escaped_path)
        else:
            # regular rooted path
            return "".join(escaped_path)
            #pass
            #escaped_path = escaped_path[1:]
    elif escaped_path[0] == u".":
        return "".join(escaped_path)
    else:
        # relative path or windows drive path
        return "/" + "".join(escaped_path)

def member_name_for_urn(member_urn, version, base_urn=None, slash_ok=True, use_unicode=False):
    filename = base_urn.RelativePath(member_urn)
    # The member is not related to the base URN, just concatenate them together.

    if filename is None:
        filename = os.path.join(
            base_urn.Parse().path, member_urn.SerializeToString())

    if filename.startswith("/"):
        # non-unc based path
        filename = filename[1:]

    if version.isLessThanOrEqual(1,0):
        if slash_ok:
            acceptable_set = PRINTABLES
        else:
            acceptable_set = PRINTABLES_NO_SLASH

        # original implementations of AFF4 (and Evimetry) escape the leading aff4://
        if filename.startswith("aff4://"):
            return filename.replace("aff4://", "aff4%3A%2F%2F")

        if not use_unicode:
            if slash_ok:
                acceptable_set = PRINTABLES
            else:
                acceptable_set = PRINTABLES_NO_SLASH

        # Escape chars which are non printable.
        escaped_filename = []
        for c in filename:
            if c in acceptable_set:
                escaped_filename.append(c)
            else:
                escaped_filename.append("%%%02x" % ord(c))
        return "".join(escaped_filename)
    elif version.isGreaterThanOrEqual(1,1):
        #return toSegmentName(filename)
        filename = filename.replace("%20", " ")
        return filename
    else:
        raise Exception("Illegal version")

#def member_name_for_urn(arn, version, base_urn):
#    a = utils.SmartUnicode(arn)
#    b = utils.SmartUnicode(base_urn)
#    return a[len(b):]

def urn_from_member_name(member, base_urn, version):
    """Returns a URN object from a zip file's member name."""
    member = utils.SmartUnicode(member)

    if version != pyaff4.version.basic_zip:
        if version.isLessThanOrEqual(1, 0):
            # Remove %xx escapes.
            member = re.sub(
                "%(..)", lambda x: chr(int("0x" + x.group(1), 0)),
                member)
        elif version.equals(1,1):
            member = member.replace(" ", "%20")

    # This is an absolute URN.
    if urllib.parse.urlparse(member).scheme == "aff4":
        result = member
    else:
        # Relative member becomes relative to the volume's URN.
        result = base_urn.Append(member, quote=False)

    return rdfvalue.URN(result)

def member_name_for_file_iri(arn):
    return arn[len("file://"):]

