# Copyright 2018-2019 Schatz Forensic Pty Ltd. All rights reserved.
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
# author bradley@evimetry.com

from __future__ import print_function
from __future__ import absolute_import
from __future__ import unicode_literals

from builtins import next
from builtins import str
from builtins import object

import argparse
import sys, os, errno, shutil, uuid
import time
import logging

from pyaff4 import container, version
from pyaff4 import lexicon, logical, escaping
from pyaff4 import rdfvalue, hashes, utils
from pyaff4 import block_hasher, data_store, linear_hasher, zip
from pyaff4 import aff4_map

#logging.basicConfig(level=logging.DEBUG)

VERBOSE = False
TERSE = False

def printImageMetadata(resolver, volume, image):
    print("\t%s <%s>" % (image.name(), trimVolume(volume.urn, image.urn)))
    with resolver.AFF4FactoryOpen(image.urn) as srcStream:
        if type(srcStream) == aff4_map.AFF4Map2:
            source_ranges = sorted(srcStream.tree)
            for n in source_ranges:
                d = n.data
                print("\t\t[%x,%x] -> %s[%x,%x]" % (
                d.map_offset, d.length, srcStream.targets[d.target_id], d.target_offset, d.length))

def printTurtle(resolver, volume):
    metadataURN = volume.urn.Append("information.turtle")
    try:
        with resolver.AFF4FactoryOpen(metadataURN) as fd:
            txt = fd.ReadAll()
            print(utils.SmartUnicode(txt))
    except:
        pass

def meta(file, password):
    with container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file)) as volume:
        printTurtle(volume.resolver, volume)

        if password != None:
            assert not issubclass(volume.__class__, container.PhysicalImageContainer)
            volume.setPassword(password[0])
            childVolume = volume.getChildContainer()
            printTurtle(childVolume.resolver, childVolume)
            for image in childVolume.images():
                printImageMetadata(childVolume.resolver, childVolume, image)
        else:
            for image in volume.images():
                printImageMetadata(volume.resolver, volume, image)



def list(file, password):
    start = time.time()
    with container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file)) as volume:
        if password != None:
            assert not issubclass(volume.__class__, container.PhysicalImageContainer)
            #volume.block_store_stream.DEBUG = True
            volume.setPassword(password[0])
            childVolume = volume.getChildContainer()
            printLogicalImageInfo(file, childVolume)
        else:
            print("Finished in %d (s)" % int(time.time() - start))
            if issubclass(volume.__class__, container.PhysicalImageContainer):
                printDiskImageInfo(file, volume)
            elif issubclass(volume.__class__, container.LogicalImageContainer):
                printLogicalImageInfo(file, volume)

def printLogicalImageInfo(file, volume):
    printVolumeInfo(file, volume)
    printCaseInfo(volume)

    for image in volume.images():
        print ("\t%s <%s>" % (image.name(), trimVolume(volume.urn, image.urn)))


def printVolumeInfo(file, volume):
    volumeURN = volume.urn

    print("AFF4Container: file://%s <%s>" % (file, str(volumeURN)))

def printCaseInfo(volume):
    caseDetails = volume.getMetadata("CaseDetails")
    if caseDetails == None:
        return
    print ("\tCase Description: %s" % caseDetails.caseDescription)
    print ("\tCase Name: %s" % caseDetails.caseName)
    print ("\tExaminer: %s" % caseDetails.examiner)

def printDiskImageInfo(file, volume):
    printVolumeInfo(file, volume)
    printCaseInfo(volume)

    image = volume.getMetadata("DiskImage")
    print ("\t%s (DiskImage)" % image.urn)
    print ("\t\tSize: %s (bytes)" % image.size)
    print ("\t\tSize: %s (bytes)" % image.size)
    print ("\t\tSectors: %s" % image.sectorCount)
    print ("\t\tBlockMapHash: %s" % image.hash)

    # the following property is to test that unknown properties are handled OK
    print ("\t\tUnknownproperty: %s" % image.foobar)

    computerInfo = volume.getMetadata("ComputeResource")
    if computerInfo != None:
        print ("\tAcquisition computer details")
        print ("\t\tSystem board vendor: %s" % computerInfo.systemboardVendor)
        print ("\t\tSystem board serial: %s" % computerInfo.systemboardSerial)
        print ("\t\tUnknownproperty: %s" % computerInfo.foobar)


class VerificationListener(object):
    def __init__(self):
        self.results = []

    def onValidBlockHash(self, a):
        pass

    def onInvalidBlockHash(self, a, b, imageStreamURI, offset):
        self.results.append("Invalid block hash comarison for stream %s at offset %d" % (imageStreamURI, offset))

    def onValidHash(self, typ, hash, imageStreamURI):
        self.results.append("Validation of %s %s succeeded. Hash = %s" % (imageStreamURI, typ, hash))

    def onInvalidHash(self, typ, a, b, streamURI):
        self.results.append("Invalid %s comarison for stream %s" % (typ, streamURI))

class LinearVerificationListener(object):
    def __init__(self):
        self.results = []

    def onValidHash(self, typ, hash, imageStreamURI):
        print ("\t\t%s Verified (%s)" % (typ, hash))

    def onInvalidHash(self, typ, hasha, hashb, streamURI):
        print ("\t\t%s Hash failure stored = %s calculated = %s)" % (typ, hasha, hashb))



def trimVolume(volume, image):
    global TERSE
    if TERSE:
        volstring = utils.SmartUnicode(volume)
        imagestring = utils.SmartUnicode(image)
        if imagestring.startswith(volstring):
            imagestring = imagestring[len(volstring):]
        return imagestring
    else:
        return image


def verify(file, password):
    with container.Container.openURNtoContainer(rdfvalue.URN.FromFileName(file)) as volume:
        if password != None:
            assert not issubclass(volume.__class__, container.PhysicalImageContainer)
            volume.setPassword(password[0])
            childVolume = volume.getChildContainer()
            printVolumeInfo(file, childVolume)
            printCaseInfo(childVolume)
            resolver = childVolume.resolver
            hasher = linear_hasher.LinearHasher2(resolver, LinearVerificationListener())
            for image in childVolume.images():
                print("\t%s <%s>" % (image.name(), trimVolume(childVolume.urn, image.urn)))
                hasher.hash(image)
        else:
            printVolumeInfo(file, volume)
            printCaseInfo(volume)
            resolver = volume.resolver

            if type(volume) == container.PhysicalImageContainer:
                image = volume.image
                listener = VerificationListener()
                validator = block_hasher.Validator(listener)
                print("Verifying AFF4 File: %s" % file)
                validator.validateContainer(rdfvalue.URN.FromFileName(file))
                for result in listener.results:
                    print("\t%s" % result)
            elif type(volume) == container.LogicalImageContainer:
                #print ("\tLogical Images:")
                hasher = linear_hasher.LinearHasher2(resolver, LinearVerificationListener())
                for image in volume.images():
                    print ("\t%s <%s>" % (image.name(), trimVolume(volume.urn, image.urn)))
                    hasher.hash(image)

def ingestZipfile(container_name, zipfiles, append, check_bytes):
    # TODO: check path in exists
    start = time.time()
    with data_store.MemoryDataStore() as resolver:


        container_urn = rdfvalue.URN.FromFileName(container_name)
        urn = None

        if not os.path.exists(container_name):
            volume = container.Container.createURN(resolver, container_urn)
            print("Creating AFF4Container: file://%s <%s>" % (container_name, volume.urn))
        else:
            volume = container.Container.openURNtoContainer(container_urn, mode="+")
            print("Appending to AFF4Container: file://%s <%s>" % (container_name, volume.urn))

        resolver = volume.resolver

        with volume as volume:
            for zipfile in zipfiles:
                basefilename = os.path.basename(zipfile)
                if basefilename.endswith(".bag.zip"):
                    basefilename = basefilename[0:len(basefilename) - len(".bag.zip")]


                filename_arn = rdfvalue.URN.FromFileName(zipfile)

                # the following coaxes our ZIP implementation to treat this file
                # as a regular old zip
                result = zip.BasicZipFile(resolver, urn=None, version=version.basic_zip)
                resolver.Set(lexicon.transient_graph, result.urn, lexicon.AFF4_TYPE, rdfvalue.URN("StandardZip"))
                resolver.Set(lexicon.transient_graph, result.urn, lexicon.AFF4_STORED, rdfvalue.URN(filename_arn))

                with resolver.AFF4FactoryOpen(result.urn, version=version.basic_zip) as zip_file:
                    for member in zip_file.members:
                        info = zip_file.members[member]
                        pathname = basefilename +  member.SerializeToString()[len(result.urn.SerializeToString()):]
                        print(pathname)

                        with resolver.AFF4FactoryOpen(member, version=version.aff4v10) as src:

                            hasher = linear_hasher.StreamHasher(src, [lexicon.HASH_SHA1, lexicon.HASH_MD5])
                            if volume.containsLogicalImage(pathname):
                                print("\tCollision: this ARN is already present in this volume.")
                                continue

                            urn = volume.writeLogicalStreamRabinHashBased(pathname, hasher, info.file_size, check_bytes)
                            #fsmeta.urn = urn
                            #fsmeta.store(resolver)
                            for h in hasher.hashes:
                                hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
                                resolver.Add(container_urn, urn, rdfvalue.URN(lexicon.standard.hash), hh)

        print ("Finished in %d (s)" % int(time.time() - start))
        return urn

def addPathNamesToVolume(resolver, volume, pathnames, recursive, hashbased):
    for pathname in pathnames:
        if not os.path.exists(pathname):
            print("Path %s not found. Skipping." % pathname)
            continue
        pathname = utils.SmartUnicode(pathname)
        print("\tAdding: %s" % pathname)
        fsmeta = logical.FSMetadata.create(pathname)
        if os.path.isdir(pathname):
            image_urn = None
            if volume.isAFF4Collision(pathname):
                image_urn = rdfvalue.URN("aff4://%s" % uuid.uuid4())
            else:
                image_urn = volume.urn.Append(escaping.arnPathFragment_from_path(pathname), quote=False)

            fsmeta.urn = image_urn
            fsmeta.store(resolver)
            resolver.Set(volume.urn, image_urn, rdfvalue.URN(lexicon.standard11.pathName), rdfvalue.XSDString(pathname))
            resolver.Add(volume.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE),
                         rdfvalue.URN(lexicon.standard11.FolderImage))
            resolver.Add(volume.urn, image_urn, rdfvalue.URN(lexicon.AFF4_TYPE), rdfvalue.URN(lexicon.standard.Image))
            if recursive:
                for child in os.listdir(pathname):
                    pathnames.append(os.path.join(pathname, child))
        else:
            with open(pathname, "rb") as src:
                hasher = linear_hasher.StreamHasher(src, [lexicon.HASH_SHA1, lexicon.HASH_MD5])
                if hashbased == False:
                    urn = volume.writeLogicalStream(pathname, hasher, fsmeta.length)
                else:
                    urn = volume.writeLogicalStreamRabinHashBased(pathname, hasher, fsmeta.length)
                fsmeta.urn = urn
                fsmeta.store(resolver)
                for h in hasher.hashes:
                    hh = hashes.newImmutableHash(h.hexdigest(), hasher.hashToType[h])
                    resolver.Add(urn, urn, rdfvalue.URN(lexicon.standard.hash), hh)

def addPathNames(container_name, pathnames, recursive, append, hashbased, password):
    with data_store.MemoryDataStore() as resolver:
        container_urn = rdfvalue.URN.FromFileName(container_name)
        urn = None
        encryption = False
        parentVolume = None

        if password != None:
            encryption = True

        if append == False:
            with container.Container.createURN(resolver, container_urn, encryption=encryption) as volume:
                print("Creating AFF4Container: file://%s <%s>" % (container_name, volume.urn))
                if password != None:
                    volume.setPassword(password[0])
                    childVolume = volume.getChildContainer()
                    addPathNamesToVolume(childVolume.resolver, childVolume, pathnames, recursive, hashbased)
                else:
                    addPathNamesToVolume(resolver, volume, pathnames, recursive, hashbased)
        else:
            with container.Container.openURNtoContainer(container_urn, mode="+") as volume:
                print("Appending to AFF4Container: file://%s <%s>" % (container_name, volume.urn))
                if password != None:
                    volume.setPassword(password[0])
                    childVolume = volume.getChildContainer()
                    addPathNamesToVolume(childVolume.resolver, childVolume, pathnames, recursive, hashbased)
                else:
                    addPathNamesToVolume(resolver, volume, pathnames, recursive, hashbased)

        return urn


def nextOrNone(iterable):
    try:
        return next(iterable)
    except:
        return None

def extractAllFromVolume(container_urn, volume, destFolder):
    printVolumeInfo(container_urn.original_filename, volume)
    resolver = volume.resolver
    for imageUrn in resolver.QueryPredicateObject(volume.urn, lexicon.AFF4_TYPE, lexicon.standard11.FileImage):
        imageUrn = utils.SmartUnicode(imageUrn)

        pathName = next(resolver.QuerySubjectPredicate(volume.urn, imageUrn, lexicon.standard11.pathName)).value
        with resolver.AFF4FactoryOpen(imageUrn) as srcStream:
            if destFolder != "-":
                drive, pathName = os.path.splitdrive(pathName) # Windows drive letters
                destFile = os.path.join(destFolder, drive[:-1], pathName.strip("/\\"))
                if not os.path.exists(os.path.dirname(destFile)):
                    try:
                        os.makedirs(os.path.dirname(destFile))
                    except OSError as exc:  # Guard against race condition
                        if exc.errno != errno.EEXIST:
                            raise
                with open(destFile, "wb") as destStream:
                    shutil.copyfileobj(srcStream, destStream)
                    print("\tExtracted %s to %s" % (pathName, destFile))

                lastWritten = nextOrNone(
                    resolver.QuerySubjectPredicate(volume.urn, imageUrn, lexicon.standard11.lastWritten))
                lastAccessed = nextOrNone(
                    resolver.QuerySubjectPredicate(volume.urn, imageUrn, lexicon.standard11.lastAccessed))
                recordChanged = nextOrNone(
                    resolver.QuerySubjectPredicate(volume.urn, imageUrn, lexicon.standard11.recordChanged))
                birthTime = nextOrNone(
                    resolver.QuerySubjectPredicate(volume.urn, imageUrn, lexicon.standard11.birthTime))
                logical.resetTimestamps(destFile, lastWritten, lastAccessed, recordChanged, birthTime)

            else:
                shutil.copyfileobj(srcStream, sys.stdout)

def extractAll(container_name, destFolder, password):
    container_urn = rdfvalue.URN.FromFileName(container_name)
    urn = None

    with container.Container.openURNtoContainer(container_urn) as volume:
        if password != None:
            assert not issubclass(volume.__class__, container.PhysicalImageContainer)
            volume.setPassword(password[0])
            childVolume = volume.getChildContainer()
            extractAllFromVolume(container_urn, childVolume, destFolder)
        else:
            extractAllFromVolume(container_urn, volume, destFolder)



def extractFromVolume(container_urn, volume, imageURNs, destFolder):
    printVolumeInfo(container_urn.original_filename, volume)
    resolver = volume.resolver
    for imageUrn in imageURNs:
        imageUrn = utils.SmartUnicode(imageUrn)

        pathName = next(resolver.QuerySubjectPredicate(volume.urn, imageUrn, volume.lexicon.pathName))

        with resolver.AFF4FactoryOpen(imageUrn) as srcStream:
            if destFolder != "-":
                pathName = escaping.arnPathFragment_from_path(pathName.value)
                while pathName.startswith("/"):
                    pathName = pathName[1:]
                drive, pathName = os.path.splitdrive(pathName) # Windows drive letters
                destFile = os.path.join(destFolder, drive[:-1], pathName.strip("/\\"))
                if not os.path.exists(os.path.dirname(destFile)):
                    try:
                        os.makedirs(os.path.dirname(destFile))
                    except OSError as exc:  # Guard against race condition
                        if exc.errno != errno.EEXIST:
                            raise
                with open(destFile, "wb") as destStream:
                    shutil.copyfileobj(srcStream, destStream, length=32 * 2014)
                    print("\tExtracted %s to %s" % (pathName, destFile))
            else:
                shutil.copyfileobj(srcStream, sys.stdout)

def extract(container_name, imageURNs, destFolder, password):
    with data_store.MemoryDataStore() as resolver:
        container_urn = rdfvalue.URN.FromFileName(container_name)
        urn = None

        with container.Container.openURNtoContainer(container_urn) as volume:
            if password != None:
                assert not issubclass(volume.__class__, container.PhysicalImageContainer)
                volume.setPassword(password[0])
                childVolume = volume.getChildContainer()
                extractFromVolume(container_urn, childVolume, imageURNs, destFolder)
            else:
                extractFromVolume(container_urn, volume, imageURNs, destFolder)



def main(argv):
    parser = argparse.ArgumentParser(description='AFF4 command line utility.')
    parser.add_argument('-v', "--verify", action="store_true",
                        help='verify the objects in the container')
    parser.add_argument("--verbose", action="store_true",
                        help='enable verbose output')
    parser.add_argument('-t', "--terse", action="store_true",
                        help='enable terse output')
    parser.add_argument('-l', "--list", action="store_true",
                        help='list the objects in the container')
    parser.add_argument('-m', "--meta", action="store_true",
                        help='dump the AFF4 metadata found in the container')
    parser.add_argument('-f', "--folder", nargs=1, action="store", default=os.getcwd(),
                        help='the destination folder for extraction of logical images')
    parser.add_argument('-r', "--recursive", action="store_true",
                        help='add files and folders recursively')
    parser.add_argument('-c', "--create-logical", action="store_true",
                        help='create an AFF4 logical container containing srcFiles')
    parser.add_argument('-x', "--extract", action="store_true",
                        help='extract objects from the container')
    parser.add_argument('-X', "--extract-all", action="store_true",
                        help='extract ALL objects from the container')
    parser.add_argument('-H', "--hash", action="store_true",
                        help='use hash based imaging for storing content')
    parser.add_argument('-p', "--paranoid", action="store_true",
                        help='do a byte-for-byte comparison when matching hashes are found with hash based imaging')
    parser.add_argument('-a', "--append", action="store_true",
                        help='append to an existing image')
    parser.add_argument('-i', "--ingest", action="store_true",
                        help='ingest a zip file into a hash based image')
    parser.add_argument('-e', "--password", nargs=1, action="store",
                        help='provide a password for encryption. This causes an encrypted container to be used.')
    parser.add_argument('aff4container', help='the pathname of the AFF4 container')
    parser.add_argument('srcFiles', nargs="*", help='source files and folders to add as logical image')


    args = parser.parse_args()
    global TERSE
    global VERBOSE
    VERBOSE = args.verbose
    TERSE = args.terse

    if args.create_logical == True:
        dest = args.aff4container
        addPathNames(dest, args.srcFiles, args.recursive, args.append, args.hash, args.password)
    elif  args.meta == True:
        dest = args.aff4container
        meta(dest, args.password)
    elif  args.list == True:
        dest = args.aff4container
        list(dest, args.password)
    elif  args.verify == True:
        dest = args.aff4container
        verify(dest, args.password)
    elif args.extract == True:
        dest = args.aff4container
        extract(dest, args.srcFiles, args.folder[0], args.password)
    elif args.extract_all == True:
        dest = args.aff4container
        extractAll(dest, args.folder[0], args.password)
    elif args.ingest == True:
        dest = args.aff4container
        ingestZipfile(dest, args.srcFiles, False, args.paranoid)


if __name__ == "__main__":
    main(sys.argv)
